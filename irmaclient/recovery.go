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
    "encoding/json"
    "io/ioutil"
    "os"
    "github.com/mhe/gabi"
    "encoding/hex"
    "crypto/rsa"
    "path/filepath"
	"github.com/tyler-smith/go-bip39"
    "strings"
)

type deviceKey struct {
    Key *big.Int
}

type backupMetadata struct {
    KeyshareServer   *keyshareServer `json:"keyshareServer"`
    EncRecoveryNonce []byte          `json:"recoveryNonce"`
    UserKeyPair      *userKeyPair    `json:"userKeyPair"`
    ServerKeyPair    *serverKeyPair  `json:"serverKeyPair"`
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
    BluePacketBytes           []byte						`json:"blue"`
    RedPacketBytes			  []byte						`json:"red"`
    decryptionKeyBluePacket	  [32]byte
    pin                       string
    transport                 *irma.HTTPTransport
    client                    *Client
    handler                   recoverySessionHandler
}

type redPacket struct {
	ServerKey string `json:"serverKey"`
	Username  string `json:"username"`
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
    RequestPhrase(callback PhraseHandler)
    ShowPhrase(phrase []string)
    OutputBackup(backup []byte)
    GetBackup(callback BackupHandler)
    RecoveryPinOk()
    RecoveryBlocked(duration int)
    RecoveryError(err error)
}

type PhraseHandler func(proceed bool, phrase []string)
type BackupHandler func(proceed bool, backup []byte)

type recoveryRequest struct {
    Delta           string			`json:"delta"`
    RedPacket		[]byte			`json:"redPacket"`
}

type recoveryInitRequest struct {
    HashedPin		string			`json:"hashedPin"`
}

type recoveryInitResponse struct {
    Status  string   `json:"status"`
    Message string   `json:"message"`
}

type recoveryServerKeyResponse struct {
    Key     string `json:"serverKey"`
    Delta   string `json:"serverDelta"`
}

func (bmeta *backupMetadata) HashedPin(pin string) string {
	nonce := curveDecrypt(bmeta.EncRecoveryNonce[:], bmeta.UserKeyPair.privateKey)
    hash := sha256.Sum256(append(nonce, []byte(pin)...))
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
func (rs *recoverySession) verifyPinAttempt(pin string, recovery bool) (
    success bool, tries int, blocked int, err error) {
    pinmsg := keysharePinMessage{Username: rs.BackupMeta.KeyshareServer.Username, Pin: rs.BackupMeta.HashedPin(pin)}
    pinresult := &keysharePinStatus{}
    if recovery {
		err = rs.transport.Post("users/recovery/verify-recovery-pin", pinresult, pinmsg)
	} else {
		err = rs.transport.Post("users/recovery/verify-pin", pinresult, pinmsg)
	}
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
func (rs *recoverySession) VerifyPin(attempts int, recovery bool) {
    if rs.BackupMeta.EncRecoveryNonce == nil {
        rs.BackupMeta.EncRecoveryNonce = rs.BackupMeta.curveEncrypt(rs.BackupMeta.KeyshareServer.Nonce, false)
    }
    if rs.pin != "" {
        success, _, _, err := rs.verifyPinAttempt(rs.pin, recovery)
        if success {
            return
        }
        rs.handler.RecoveryError(err)
    } else {
        rs.handler.RequestPin(attempts, PinHandler(func (proceed bool, pin string) {
        if !proceed {
            rs.handler.RecoveryCancelled()
            return
        }
        rs.pin = pin
        success, attemptsRemaining, blocked, err := rs.verifyPinAttempt(pin, recovery)
        if err != nil {
            rs.handler.RecoveryError(err)
            return
        }
        if blocked != 0 {
            rs.handler.RecoveryBlocked(blocked)
            return
        }
        if success {
            rs.handler.RecoveryPinOk()
            success = true
            return
        }
        // Not successful but no error and not yet blocked: try again
        rs.VerifyPin(attemptsRemaining, recovery)
        }))
    }
}

// Computes new delta and sends that to the keyshare server.
// Keyshare server returns decryption key and that key is stored
func (rs *recoverySession) renewDeviceKeys() (err error) {
    delta, err := gabi.RandomBigInt(128)
	if err != nil {
        return
    }
    rr := recoveryRequest{delta.String(), rs.RedPacketBytes}
    resp := &recoveryServerKeyResponse{}
    rs.transport.Post("users/recovery/new-device", resp, rr)

    serverDelta, passed := new(big.Int).SetString(resp.Delta, 10)
    if !passed {
    	return errors.New("Invalid response server delta!")
	}
    rs.BackupMeta.KeyshareServer.DeviceKey = &deviceKey{delta.Xor(delta, serverDelta)}
    m, err := rs.client.storage.LoadKeyshareServers()
    if err != nil{
        return err
    }
    m[rs.BackupMeta.KeyshareServer.SchemeManagerIdentifier] = rs.BackupMeta.KeyshareServer
    rs.client.storage.StoreKeyshareServers(m)
    arr, err := hex.DecodeString(resp.Key)
	copy(rs.decryptionKeyBluePacket[:], arr)
    return nil
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

    rp := redPacket{hex.EncodeToString(rs.decryptionKeyBluePacket[:]), rs.BackupMeta.KeyshareServer.Username}
    rpBytes, _ := json.Marshal(rp)
    rs.RedPacketBytes = rs.rsaEncrypt(rpBytes)
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

func curveDecrypt (ciphertext []byte, privateKey [32]byte) (plain []byte) {
    dummyPrivAuthKey := new([32]byte) // Zero initialized auth key, authentication is not needed
    dummyPubAuthKey := new([32]byte)
    curve25519.ScalarBaseMult(dummyPubAuthKey, dummyPrivAuthKey)

    var decryptNonce [24]byte
    copy(decryptNonce[:], ciphertext[:24])

    plain, ok := box.Open(nil, ciphertext[24:], &decryptNonce, dummyPubAuthKey, &privateKey)
    if !ok {
        panic("decryption error")
    }
    return
}

func genKeyPair(phrase []byte) (pair *userKeyPair, err error) {
    //pub, priv, err := box.GenerateKey(rand.Reader) // How to do it normally
    err = nil
    key, err := scrypt.Key(phrase, []byte(""), 1<<16, 16, 4, 32) // Unsalted because phrase is based on key
    if err != nil {
        return
    }
    pair = &userKeyPair{}
    copy(pair.privateKey[:], key[:32])
    curve25519.ScalarBaseMult(&pair.PublicKey, &pair.privateKey)
    return
}

func  (rs *recoverySession) rsaEncrypt(toEnc []byte) ([]byte) {
    rng := rand.Reader
    pub, err := rs.client.loadServerRecoveryPubKey(rs.BackupMeta.KeyshareServer)
    if err != nil {
        panic("Recovery public key could not be found!")
    }

    ciphertext, err := rsa.EncryptPKCS1v15(rng, pub, toEnc)
    if err != nil {
        panic("Error from encryption")
    }
    return ciphertext
}

func (c *Client) loadServerRecoveryPubKey(kss *keyshareServer) (key *rsa.PublicKey, err error) {
    file, err := os.Open(filepath.Join(c.Configuration.Path, kss.SchemeManagerIdentifier.String()+"/recovery_public_key.key"))
    if err != nil {
        return nil, err
    }
    keyBytes, err := ioutil.ReadAll(file)
    if err != nil {
        return nil, err
    }
    keyDec := string(keyBytes)
    pub := rsa.PublicKey{big.NewInt(0), 65537}
    pub.N.SetString(keyDec, 10)
    return &pub, nil
}

func (client *Client) InitRecovery(h recoverySessionHandler) {
    var phrase [16]byte
    if _, err := io.ReadFull(rand.Reader, phrase[:]); err != nil {
        panic("Not enough randomness")
    }

    pin := ""
    var metas []backupMetadata
    for _,kss := range client.keyshareServers{
        var salt [24]byte
        if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
            panic(err)
        }
        pair, err := genKeyPair(phrase[:])
        if err != nil {
            panic(err)
        }

        mnemonic, _ := bip39.NewMnemonic(phrase[:])
        h.ShowPhrase(strings.Split(mnemonic, " "))

        kssStore := *kss
        kssStore.DeviceKey = nil

        rs := recoverySession{
            BackupMeta:            &backupMetadata{
                KeyshareServer:   &kssStore,
                EncRecoveryNonce: nil,
                UserKeyPair:      pair,
                ServerKeyPair:    nil,
            },
            BluePacketBytes:           nil,
            pin:                       pin,
            transport:                 irma.NewHTTPTransport(kss.URL),
            client:                    client,
            handler:				   h,
        }

        rs.VerifyPin(-1, false)
        pin = rs.pin

        rs.BackupMeta.EncRecoveryNonce = rs.BackupMeta.curveEncrypt(salt[:], false)
        status := recoveryInitResponse{}
        err = rs.transport.Post("users/recovery/setup", &status, recoveryInitRequest{
            HashedPin: rs.BackupMeta.HashedPin(pin),
        })
        if err != nil {
            panic("Unexpected error occured at recovery server")
        }
        if status.Status != "success" {
            panic("Server error: " + status.Message)
        }
        metas = append(metas, *rs.BackupMeta)
    }
    err := client.storage.StoreRecoveryMetas(metas)
    if err != nil {
    	panic("Backup could not be stored")
	}
    return
}

func (client *Client) MakeBackup(h recoverySessionHandler) (err error) {
    var backups []recoverySession
    metas, err := client.storage.LoadRecoveryMeta()
    if err != nil {
        return
    }
    for _, meta := range metas {
        b := client.storageToBackup(meta.KeyshareServer)

        // Key in file for now
        var keyBytes []byte
        keyBytes, err = ioutil.ReadFile("/tmp/recoveryPrivateKey")
        hex.Decode(meta.UserKeyPair.privateKey[:], keyBytes)
        rs := recoverySession{
            BackupMeta:                &meta,
            pin:                       "",
            handler:				   h,
            client:					   client,
        }

        rs.serverEncrypt(b)
        backups = append(backups, rs)
    }

    b, err := json.Marshal(backups)
    if err != nil {
    	return
	}
    backup := backups[0].BackupMeta.curveEncrypt(b, false) // The user private key should be the same for all backups
    h.OutputBackup(backup)
    return nil
}

func (c *Client) StartRecovery(handler recoverySessionHandler) {
    pin := ""
    handler.GetBackup(func (proceed bool, backup []byte) {
    	if proceed {
			handler.RequestPhrase(func(proceed bool, phrase []string) {
				if proceed {
					phraseBytes, err := bip39.EntropyFromMnemonic(strings.Join(phrase, " "))
					if err != nil {
						return
					}
					key, err := genKeyPair(phraseBytes)
					if err != nil {
						return
					}

					sessionsBytes := curveDecrypt(backup, key.privateKey)
					var sessions []recoverySession
					json.Unmarshal(sessionsBytes, &sessions)

					for _, rs := range sessions {
						rs.transport = irma.NewHTTPTransport(rs.BackupMeta.KeyshareServer.URL)
						rs.client = c
						rs.handler = handler
						rs.pin = pin
						rs.BackupMeta.UserKeyPair = key

						rs.VerifyPin(-1, true)
						pin = rs.pin
						rs.renewDeviceKeys()

						backupBytes := rs.aesDecrypt(rs.BluePacketBytes)
						c.backupToStorage(backupBytes, rs.BackupMeta.KeyshareServer)
					}
				}
			})
		}
	})
}

func (c *Client) getSignatures(needed []string) (sigs map[string][]byte, err error){
    sigs = make(map[string][]byte)
    for _, sig := range needed {
    	// Only include signatures as specified in needed
        b, err := ioutil.ReadFile(c.storage.path(sig))
        if err != nil {
            return nil, err
        }
        sigs[sig] = b
    }
    return
}

func (c *Client) storeSignatures (sigs map[string][]byte){
    if _, err := os.Stat(c.storage.path("sigs")); os.IsNotExist(err) {
        os.Mkdir(c.storage.path("sigs"), 0755)
    }
    for file, content := range sigs {
        if _, err := os.Stat(c.storage.path(file)); err == nil {
            os.Remove(c.storage.path(file))
        }
        ioutil.WriteFile(c.storage.path(file), content, 0600)
    }
}

func (c *Client) storageToBackup(kss *keyshareServer) (result []byte) {
    var selected []*irma.AttributeList
    var signatureFiles []string
    for _, attrs := range c.attributes {
        for _, attr := range attrs {
            if attr.Info().SchemeManagerID == kss.SchemeManagerIdentifier { // Assumption: one kss per scheme
                // Skip attributes that do not belong to keyshareserver kss
                selected = append(selected, attr)
                signatureFiles = append(signatureFiles, c.storage.signatureFilename(attr))
            }
        }
    }
    sigs, err := c.getSignatures(signatureFiles)
    if err != nil {
        panic("Signatures could not be converted") // TODO Add error handling
    }
    sigsJson, err := json.Marshal(sigs) // TODO Add error handling
    if err != nil {
    	panic("JSON library produced invalid JSON")
	}
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

func (c *Client) backupToStorage(backupFile []byte, kss *keyshareServer) (err error) {
    b := backup{}
    if err := json.Unmarshal(backupFile, &b); err != nil {
        return err
    }
    sigs := make(map[string][]byte)
    err = json.Unmarshal(b.Signatures, &sigs)
    if err != nil {
    	return err
	}

	// Delete previous files
	os.Remove(c.storage.storagePath)
    os.Mkdir(c.storage.storagePath, 0744)

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

    c, err = New(
		c.storage.storagePath,
		c.irmaConfigurationPath,
		c.androidStoragePath,
		c.handler,
	)
    return err
}
