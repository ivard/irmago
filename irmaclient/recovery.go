package irmaclient

import (
	"math/big"
	"crypto/rand"
	"io"
	"github.com/privacybydesign/irmago"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"github.com/go-errors/errors"
	"crypto/aes"
	"crypto/cipher"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/curve25519"
	"fmt"
	"encoding/json"
	"io/ioutil"
	"os"
)

type deviceKey struct {
	Key *big.Int
}

type backupMetadata struct {
	KeyshareServer  *keyshareServer	 `json:"keyshareServer"`
	RecoveryNonce   []byte			 `json:"recoveryNonce"`
	UserKeyPair		*userKeyPair 	 `json:"userKeyPair"`
	ServerKeyPair	*serverKeyPair   `json:"serverKeyPair"`
}

type userKeyPair struct {
	PublicKey  [32]byte `json:"publicRecoveryKey"`
	privateKey [32]byte
}

type serverKeyPair struct {
	PublicKey       		[32]byte         `json:"publicDeviceKey"`
	privateKey      		[32]byte
}

type recoverySession struct {
	BackupMeta                *backupMetadata				`json:"meta"`
	recoveryServerKeyResponse *recoveryServerKeyResponse
	BluePacketBytes           []byte						`json:"blue"`
	RedPacketBytes			  []byte						`json:"red"`
	decryptionKeyBluePacket	  [32]byte
	pin                       string
	transport                 *irma.HTTPTransport
	storage                   *storage
}

type backup struct {
	Signatures  []byte                `json:"signatures"`
	SecretKey   *secretKey            `json:"secretKey"`
	Attributes  []*irma.AttributeList `json:"attrs"`
	Paillier    *paillierPrivateKey   `json:"paillier"`
	Logs        []*LogEntry           `json:"logs"`
	Preferences Preferences           `json:"preferences"`
	Updates     []update              `json:"updates"`
}

type recoverySessionHandler interface {
	RecoveryCancelled()
	RequestPin(remainingAttempts int, callback PinHandler)
	RecoveryPinOk()
	RecoveryBlocked(duration int)
	RecoveryError(err error)
}

type recoveryRequest struct {
	Delta           []byte			`json:"delta"`
}

type recoveryInitRequest struct {
	HashedPin		string			`json:"hashedPin"`
}

type recoveryInitResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type recoveryServerKeyResponse struct {
	Key			    [32]byte `json:"serverKey"`
}

// We implement the handler for the keyshare protocol
var _ recoverySessionHandler = (*recoverySession)(nil)

func (bmeta *backupMetadata) HashedPin(pin string) string {
	hash := sha256.Sum256(append(bmeta.RecoveryNonce[:], []byte(pin)...))
	// We must be compatible with the old Android app here,
	// which uses Base64.encodeToString(hash, Base64.DEFAULT),
	// which appends a newline.
	return base64.StdEncoding.EncodeToString(hash[:]) + "\n"
}

// Verify the specified pin at each of the keyshare servers involved in the specified recovery session.
// - If the pin did not verify at one of the keyshare servers but there are attempts remaining,
// the amount of remaining attempts is returned as the second return value.
// - If the pin did not verify at one of the keyshare servers and there are no attempts remaining,
// the amount of time for which we are blocked at the keyshare server is returned as the third
// parameter.
// - If this or anything else (specified in err) goes wrong, success will be false.
// If all is ok, success will be true.
func (rs *recoverySession) verifyPinAttempt(pin string) (
	success bool, tries int, blocked int, err error) {
	pinmsg := keysharePinMessage{Username: rs.BackupMeta.KeyshareServer.Username, Pin: rs.BackupMeta.HashedPin(pin)}
	pinresult := &keysharePinStatus{}
	err = rs.transport.Post("users/recovery/verify-pin", pinresult, pinmsg)
	if err != nil {
		return
	}

	switch pinresult.Status {
	case kssPinSuccess:
		rs.BackupMeta.KeyshareServer.token = pinresult.Message
		rs.transport.SetHeader(kssUsernameHeader, rs.BackupMeta.KeyshareServer.Username)
		rs.transport.SetHeader(kssAuthHeader, rs.BackupMeta.KeyshareServer.token)
	case kssPinFailure:
		tries, err = strconv.Atoi(pinresult.Message)
		return
	case kssPinError:
		blocked, err = strconv.Atoi(pinresult.Message)
		return
	default:
		err = errors.New("Keyshare server returned unrecognized PIN status")
		return
	}

	success = true
	return
}

// Ask for a pin, repeatedly if necessary, and either continue the keyshare protocol
// with authorization, or stop the keyshare protocol and inform of failure.
func (rs *recoverySession) VerifyPin(attempts int) {
	if rs.BackupMeta.RecoveryNonce == nil {
		rs.BackupMeta.RecoveryNonce = rs.BackupMeta.KeyshareServer.Nonce
	}
	if rs.pin != "" {
		success, _, _, err := rs.verifyPinAttempt(rs.pin)
		if success {
			return
		}
		rs.RecoveryError(err)
	} else {
		rs.RequestPin(attempts, PinHandler(func (proceed bool, pin string) {
		if !proceed {
			rs.RecoveryCancelled()
			return
		}
		rs.pin = pin
		success, attemptsRemaining, blocked, err := rs.verifyPinAttempt(pin)
		if err != nil {
			rs.RecoveryError(err)
			return
		}
		if blocked != 0 {
			rs.RecoveryBlocked(blocked)
			return
		}
		if success {
			rs.RecoveryPinOk()
			rs.renewDeviceKeys() // TODO Wat moet er gebeuren als de PIN correct is?
			return
		}
		// Not successful but no error and not yet blocked: try again
		rs.VerifyPin(attemptsRemaining)
		}))
	}
}

func (rs *recoverySession) storeBackup(bluePacket []byte) {
	// TODO Implement
}

func (rs *recoverySession) renewDeviceKeys() {
	deltaBytes := new([32]byte)
	io.ReadFull(rand.Reader, deltaBytes[:])
	rr := recoveryRequest{deltaBytes[:]}
	rs.recoveryServerKeyResponse = &recoveryServerKeyResponse{}
	rs.transport.Post("users/recovery/new-device", rs.recoveryServerKeyResponse, rr)

	//greenPacket := rs.RedPacket.aesDecrypt(rs.bluePacketBytes)
	//decryptedBackup := rs.RedPacket.curveDecrypt(greenPacket)

	//rs.RedPacket.KeyshareServer.DeviceKey.Key = new(big.Int)
	//rs.RedPacket.KeyshareServer.DeviceKey.Key.SetBytes(deltaBytes[:])

	//rs.storeBackup(decryptedBackup)
}

func (rs *recoverySession) serverEncrypt(data []byte) () {
	if _, err := io.ReadFull(rand.Reader, rs.decryptionKeyBluePacket[:]); err != nil {
		panic(err.Error())
	}
	block, _ := aes.NewCipher(rs.decryptionKeyBluePacket[:])
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	rs.BluePacketBytes = gcm.Seal(nonce, nonce, data, nil)
	rs.RedPacketBytes = rs.BackupMeta.curveEncrypt(rs.decryptionKeyBluePacket[:], true) // TODO needs identifier user in packet
	return
}

func (rs *recoverySession) aesDecrypt(data []byte) (plaintext []byte) {
	block, err := aes.NewCipher(rs.decryptionKeyBluePacket[:])
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return
}

func (bmeta *backupMetadata) curveEncrypt (plain []byte, server bool) (ciphertext []byte) {
	dummyAuthKey := new([32]byte) // Zero initialized auth key, authentication is not needed

	// Server boolean indicates whether the key of the user must be used, otherwise only the user keys are used
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	var enc *[32]byte
	if server {
		enc = &bmeta.ServerKeyPair.PublicKey
	} else {
		enc = &bmeta.UserKeyPair.PublicKey
	}
	// This encrypts msg and appends the result to the nonce.
	ciphertext = box.Seal(nonce[:], plain, &nonce, enc, dummyAuthKey)
	return
}

func (bmeta *backupMetadata) curveDecrypt (ciphertext []byte) (plain []byte) {
	dummyPrivAuthKey := new([32]byte) // Zero initialized auth key, authentication is not needed
	dummyPubAuthKey := new([32]byte)
	curve25519.ScalarBaseMult(dummyPubAuthKey, dummyPrivAuthKey)

	var decryptNonce [24]byte
	copy(decryptNonce[:], ciphertext[:24])
	plain, ok := box.Open(nil, ciphertext[24:], &decryptNonce, dummyPrivAuthKey, &bmeta.UserKeyPair.privateKey)
	if !ok {
		panic("decryption error")
	}
	return
}

func genKeyPair(salt []byte, phrase []byte) (pair *userKeyPair, err error) {
	//pub, priv, err := box.GenerateKey(rand.Reader) // How to do it normally
	err = nil
	key, err := scrypt.Key(phrase, salt, 1<<16, 16, 4, 32)
	if err != nil {
		return
	}
	copy(pair.privateKey[:], key[:32])
	curve25519.ScalarBaseMult(&pair.PublicKey, &pair.privateKey)
	return
}

func initRecovery(client *Client) {
	var phrase [16]byte
	if _, err := io.ReadFull(rand.Reader, phrase[:]); err != nil {
		panic("Not enough randomness")
	}

	pin := ""
	var metas []*backupMetadata
	for _,kss := range client.keyshareServers{
		var salt [24]byte
		if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
			panic(err)
		}
		pair, err := genKeyPair(salt[:], phrase[:])
		if err != nil {
			panic(err)
		}

		session := recoverySession{
			BackupMeta:            &backupMetadata{
				KeyshareServer: kss,
				RecoveryNonce:  nil,
				UserKeyPair:    pair,
				ServerKeyPair:  nil,
			},
			recoveryServerKeyResponse: nil,
			BluePacketBytes:           nil,
			pin:                       pin,
			transport:                 irma.NewHTTPTransport(kss.URL),
			storage:                   &client.storage,
		}

		session.VerifyPin(-1)
		pin = session.pin

		session.BackupMeta.RecoveryNonce = salt[:]
		status := recoveryInitResponse{}
		err = session.transport.Post("users/recovery/init", &status, recoveryInitRequest{
			HashedPin: session.BackupMeta.HashedPin(pin),
		})
		if err != nil {
			panic("Unexpected error occured at recovery server")
		}
		if status.Status != "completed" {
			panic("Server error: " + status.Message)
		}
		metas = append(metas, session.BackupMeta)
	}
	client.storage.StoreRecoveryMetas(metas)
	return
}

func (client *Client) makeBackup() (backup []byte, err error) {
	backups := make(map[backupMetadata]recoverySession)
	metas, err := client.storage.LoadRecoveryMeta()
	if err != nil {
		panic("Backup information could not be loaded")
	}
	var meta *backupMetadata // This kss is back-upped
	for _, meta = range metas {
		b := client.storageToBackup(meta.KeyshareServer)
		b = meta.curveEncrypt(b, false)
		rs := recoverySession{
			BackupMeta:                meta,
			recoveryServerKeyResponse: nil,
			BluePacketBytes:           nil,
			RedPacketBytes:            nil,
			decryptionKeyBluePacket:   nil,
			pin:                       "",
			transport:                 nil,
			storage:                   nil,
		}
		rs.serverEncrypt(b)
		backups[*meta] = rs
	}
	return json.Marshal(backups[*meta]) // For now only one kss
}

func startRecovery(handler recoverySessionHandler, storage *storage) {
	pin := ""
	var rs recoverySession
	storage.load(rs, "backup")
	// TODO Add support multiple keyshare servers
	//for _, rs := range sessions {
		rs.transport = irma.NewHTTPTransport(rs.BackupMeta.KeyshareServer.URL)
		rs.pin = pin

		//rs.VerifyPin(-1) Skip PIN check for now
		pin = rs.pin

		resp := recoveryServerKeyResponse{}
		rs.transport.Get("users/recovery/perform", resp)
		//rs.decryptionKeyBluePacket = resp.Key
		//rs.BluePacketBytes = rs.aesDecrypt(rs.RedPacketBytes)
		//backup := rs.backupMeta.curveDecrypt(rs.bluePacketBytes)

		rs.storeBackup(rs.BluePacketBytes)
	//}
}

func (c *Client) getSignatures(needed []string) (sigs map[string][]byte, err error){
	sigs = make(map[string][]byte)
	for _, sig := range needed {
		b, err := ioutil.ReadFile(c.storage.path(sig))
		if err != nil {
			return nil, err
		}
		sigs[sig] = b
	}
	return
}

func (c *Client) storeSignatures (sigs map[string][]byte){
	for file, content := range sigs {
		if _, err := os.Stat(c.storage.path(file)); err == nil {
			os.Remove(c.storage.path(file))
		}
		ioutil.WriteFile(c.storage.path(file), content, 0644)
	}
}

func (c *Client) storageToBackup(kss *keyshareServer) (result []byte) {
	var selected []*irma.AttributeList
	var signatureFiles []string
	for _, attrs := range c.attributes {
		for _, attr := range attrs {
			if c.keyshareServers[attr.Info().SchemeManagerID] == kss {
				selected = append(selected, attr)
				signatureFiles = append(signatureFiles, c.storage.signatureFilename(attr))
			}
		}
	}
	sigs, _ := c.getSignatures(signatureFiles) // TODO Add error handling
	sigsJson, _ := json.Marshal(sigs) // TODO Add error handling
	b := backup{
		Signatures:  sigsJson,
		SecretKey:   c.secretkey,
		Attributes:  selected,
		Paillier:    c.paillierKey(true),
		Logs:        c.logs,
		Preferences: c.Preferences,
		Updates:     c.updates,
	}
	backup, err := json.Marshal(b)
	if err != nil {
		panic("Subset of Attributes could not be marshalled in JSON")
	}
	return backup
}

func (c *Client) backupToStorage(backupFile []byte, kss *keyshareServer) (error) {
	b := backup{}
	if err := json.Unmarshal(backupFile, &b); err != nil {
		return err
	}
	sigs := make(map[string][]byte)
	json.Unmarshal(b.Signatures, sigs)
	c.storeSignatures(sigs)
	c.keyshareServers[kss.SchemeManagerIdentifier] = kss
	c.storage.StoreKeyshareServers(c.keyshareServers)
	c.storage.StoreSecretKey(b.SecretKey)
	c.storage.StorePreferences(b.Preferences)
	c.storage.StorePaillierKeys(b.Paillier)
	c.storage.StoreUpdates(b.Updates)
	c.storage.StoreLogs(b.Logs)

	for _, a := range b.Attributes {
		a.MetadataAttribute = irma.MetadataFromInt(a.Ints[0], c.storage.Configuration)
		val, ok := c.attributes[a.CredentialType().Identifier()]
		if !ok {
			c.attributes[a.Info().CredentialTypeID] = []*irma.AttributeList{a}
		} else {
			c.attributes[a.Info().CredentialTypeID] = append(val, a)
		}
	}
	c.storage.StoreAttributes(c.attributes)
	c.ParseAndroidStorage()
	return nil
}

func (rs *recoverySession) RecoveryCancelled() {
	fmt.Println("Recovery cancelled")
}

func (rs *recoverySession) RequestPin(remainingAttempts int, callback PinHandler) {
	fmt.Println("Recovery PIN")
}

func (rs *recoverySession) RecoveryPinOk() {
	fmt.Println("Recovery Pin OK")
}

func (rs *recoverySession) RecoveryBlocked(duration int) {
	fmt.Println("Recovery blocked")
}

func (rs *recoverySession) RecoveryError(err error) {
	fmt.Println("Recovery error")
}
