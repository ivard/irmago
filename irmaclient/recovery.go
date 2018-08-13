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
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/scrypt"
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
	PublicEncryptionKey     [32]byte         `json:"publicRecoveryKey"`
	privateEncryptionKey    [32]byte
	PrivateAuthKey  		[32]byte         `json:"privateAuthKey"` // TODO: Should maybe not be included in metadata
	PublicAuthKey     		[32]byte		 `json:"publicAuthKey"`
}

type serverKeyPair struct {
	PublicKey       		[32]byte         `json:"publicDeviceKey"`
	privateKey      		[32]byte
}

type recoverySession struct {
	backupMeta                *backupMetadata
	recoveryServerKeyResponse *recoveryServerKeyResponse
	bluePacketBytes           []byte
	sessionHandler            recoverySessionHandler
	pin                       string
	transport                 *irma.HTTPTransport
	storage                   *storage
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

// Recovery PIN uses private recovery key in the hash
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
	pinmsg := keysharePinMessage{Username: rs.backupMeta.KeyshareServer.Username, Pin: rs.backupMeta.HashedPin(pin)}
	pinresult := &keysharePinStatus{}
	err = rs.transport.Post("users/recovery/verify-pin", pinresult, pinmsg)
	if err != nil {
		return
	}

	switch pinresult.Status {
	case kssPinSuccess:
		rs.backupMeta.KeyshareServer.token = pinresult.Message
		rs.transport.SetHeader(kssUsernameHeader, rs.backupMeta.KeyshareServer.Username)
		rs.transport.SetHeader(kssAuthHeader, rs.backupMeta.KeyshareServer.token)
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
	if rs.backupMeta.RecoveryNonce == nil {
		rs.backupMeta.RecoveryNonce = rs.backupMeta.KeyshareServer.Nonce
	}
	if rs.pin != "" {
		success, _, _, err := rs.verifyPinAttempt(rs.pin)
		if success {
			return
		}
		rs.sessionHandler.RecoveryError(err)
	} else {
		rs.sessionHandler.RequestPin(attempts, PinHandler(func (proceed bool, pin string) {
		if !proceed {
			rs.sessionHandler.RecoveryCancelled()
			return
		}
		rs.pin = pin
		success, attemptsRemaining, blocked, err := rs.verifyPinAttempt(pin)
		if err != nil {
			rs.sessionHandler.RecoveryError(err)
			return
		}
		if blocked != 0 {
			rs.sessionHandler.RecoveryBlocked(blocked)
			return
		}
		if success {
			rs.sessionHandler.RecoveryPinOk()
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

/* Does not seem necessary
func (rp *redPacket) aesEncrypt(data []byte) (ciphertext []byte) {
	rp.AesKey = new([32]byte)[:]
	if _, err := io.ReadFull(rand.Reader, rp.AesKey); err != nil {
		panic(err.Error())
	}
	block, _ := aes.NewCipher(rp.AesKey)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext = gcm.Seal(nonce, nonce, data, nil)
	return
}

func (rp *redPacket) aesDecrypt(data []byte) (plaintext []byte) {
	block, err := aes.NewCipher(rp.AesKey)
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
} */

func (bmeta *backupMetadata) curveEncrypt (plain []byte) (ciphertext []byte) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	msg := []byte("Alas, poor Yorick! I knew him, Horatio")
	// This encrypts msg and appends the result to the nonce.
	ciphertext = box.Seal(nonce[:], msg, &nonce, &bmeta.UserKeyPair.PublicEncryptionKey, &bmeta.UserKeyPair.PrivateAuthKey)
	return
}

func (bmeta *backupMetadata) curveDecrypt (ciphertext []byte) (plain []byte) {
	var decryptNonce [24]byte
	copy(decryptNonce[:], ciphertext[:24])
	plain, ok := box.Open(nil, ciphertext[24:], &decryptNonce, &bmeta.UserKeyPair.PublicAuthKey, &bmeta.UserKeyPair.privateEncryptionKey)
	if !ok {
		panic("decryption error")
	}
	return
}

func genKeyPair(salt []byte, phrase []byte) (pair *userKeyPair, err error) {
	//pub, priv, err := box.GenerateKey(rand.Reader) // How to do it normally
	err = nil
	key, err := scrypt.Key(phrase, salt, 1<<16, 16, 4, 64)
	if err != nil {
		return
	}
	copy(pair.privateEncryptionKey[:], key[:32])
	copy(pair.PrivateAuthKey[:], key[32:64])
	curve25519.ScalarBaseMult(&pair.PublicEncryptionKey, &pair.privateEncryptionKey)
	curve25519.ScalarBaseMult(&pair.PublicAuthKey, &pair.PrivateAuthKey)
	return
}

func initRecovery(client *Client, rh *recoverySessionHandler) {
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
			backupMeta:            &backupMetadata{
				KeyshareServer: kss,
				RecoveryNonce:  nil,
				UserKeyPair:    pair,
				ServerKeyPair:  nil,
			},
			recoveryServerKeyResponse: nil,
			bluePacketBytes:           nil,
			sessionHandler:            rh,
			pin:                       pin,
			transport:                 irma.NewHTTPTransport(kss.URL),
			storage:                   &client.storage,
		}

		session.VerifyPin(-1)
		pin = session.pin

		session.backupMeta.RecoveryNonce = salt[:]
		status := recoveryInitResponse{}
		err = session.transport.Post("users/recovery/init", &status, recoveryInitRequest{
			HashedPin: session.backupMeta.HashedPin(pin),
		})
		if err != nil {
			panic("Unexpected error occured at recovery server")
		}
		if status.Status != "completed" {
			panic("Server error: " + status.Message)
		}
		metas = append(metas, session.backupMeta)
	}
	client.storage.StoreRecoveryMetas(metas)
	return
}

func startRecovery(handler recoverySessionHandler, storage *storage) {
	pin := ""
	backup := new([]byte) // TODO Load backup
	sessions := parseBackup(backup)

	for _, rs := range sessions {
		rs.transport = irma.NewHTTPTransport(rs.backupMeta.KeyshareServer.URL)
		rs.pin = pin

		rs.VerifyPin(-1)
		pin = rs.pin

		// decryptBackup
	}
}

func parseBackup(backup *[]byte) (sessions []*recoverySession) {
	//TODO
	return nil
}
