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
    "log"
)

type deviceKey struct {
    Key *big.Int
}

type backupMetadata struct {
    KeyshareServer   *keyshareServer `json:"keyshareServer"`
    EncRecoveryNonce []byte          `json:"recoveryNonce"`
    UserKeyPair      *userKeyPair    `json:"userKeyPair"`
    ServerKeyPair    *serverKeyPair  `json:"serverKeyPair,omitempty"`
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
    Signatures      []byte                `json:"signatures"`
    SecretKey       *secretKey            `json:"secretKey"`
    Attributes      []*irma.AttributeList `json:"attrs"`
    Paillier        *paillierPrivateKey   `json:"paillier"`
    Logs            []*LogEntry           `json:"logs"`
    Preferences     Preferences           `json:"preferences"`
    Updates         []update              `json:"updates"`
    KeyshareServer  *keyshareServer       `json:"keyshareServer"`
}

type recoverySessionHandler interface {
    RecoveryCancelled()
    RecoveryInitSuccess()
    RecoveryPerformed(newClient *Client)
    RequestPin(remainingAttempts int, callback PinHandler)
    RequestPhrase(callback PhraseHandler)
    ShowPhrase(phrase []string)
    OutputBackup(backup []byte)
    GetBackup(callback BackupHandler)
    RecoveryPinOk()
    RecoveryBlocked(duration int)
    RecoveryError(err error)
    RecoveryPhraseIncorrect(err error)
}

type PhraseHandler func(proceed bool, phrase []string)
type BackupHandler func(proceed bool, backup []byte)

type recoveryRequest struct {
    Delta           string			`json:"delta"`
    HashedPin       string          `json:"newHashedPin"`
    RedPacket		[]byte			`json:"redPacket"`
}

type recoveryInitRequest struct {
    HashedPin		string			`json:"hashedPin"`
}

type recoveryInitResponse struct {
    Status  string   `json:"status"`
    Message string   `json:"message"`
}

type recoveryNewDeviceResponse struct {
    ServerDeltaHash string `json:"serverDeltaHash"`
}

type recoveryServerKeyResponse struct {
    Key     string `json:"serverKey"`
    Delta   string `json:"serverDelta"`
}

func (bmeta *backupMetadata) HashedPin(pin string) string {
	nonce, err := curveDecrypt(bmeta.EncRecoveryNonce[:], bmeta.UserKeyPair.privateKey)
	if err != nil {
		// Should be impossible
		panic("Password nonce is not valid")
	}
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

// Ask for a pin, repeatedly if necessary, and either continue the recovery protocol
// with authorization, or stop the keyshare protocol and inform of failure.
func (rs *recoverySession) VerifyPin(attempts int, recovery bool) {
    if rs.BackupMeta.EncRecoveryNonce == nil {
        // Should only happen in case of recovery initialization
        rs.BackupMeta.EncRecoveryNonce = rs.BackupMeta.curveEncrypt(rs.BackupMeta.KeyshareServer.Nonce, false)
    }
    if rs.pin != "" {
        success, _, _, err := rs.verifyPinAttempt(rs.pin, recovery)
        if success {
            return
        }
        rs.pin = "" // PIN was apparently not correct
        rs.handler.RecoveryError(err)
    } else {
        rs.handler.RequestPin(attempts, PinHandler(func (proceed bool, pin string) {
            if !proceed {
                rs.handler.RecoveryCancelled()
                return
            }
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
                rs.pin = pin
                rs.handler.RecoveryPinOk()
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
    newDevResp := &recoveryNewDeviceResponse{}
    rs.transport.Get("users/recovery/request-new-device", newDevResp)

    delta, err := gabi.RandomBigInt(128)
	if err != nil {
        return
    }

	rs.BackupMeta.KeyshareServer.Nonce = make([]byte, 32)
    _, err = io.ReadFull(rand.Reader, rs.BackupMeta.KeyshareServer.Nonce)

    rr := recoveryRequest{delta.String(), rs.BackupMeta.KeyshareServer.HashedPin(rs.pin), rs.RedPacketBytes}
    resp := &recoveryServerKeyResponse{}
    rs.transport.Post("users/recovery/new-device", resp, rr)

	hash := sha256.Sum256([]byte(resp.Delta))
	if hex.EncodeToString(hash[:]) != newDevResp.ServerDeltaHash {
		return errors.New("Commitment hash mismatch")
	}
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

func (rs *recoverySession) serverEncrypt(data []byte) (err error) {
    if _, err := io.ReadFull(rand.Reader, rs.decryptionKeyBluePacket[:]); err != nil {
        return err
    }
    block, _ := aes.NewCipher(rs.decryptionKeyBluePacket[:])
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return err
    }
    rs.BluePacketBytes = gcm.Seal(nonce, nonce, data, nil)

    rp := redPacket{hex.EncodeToString(rs.decryptionKeyBluePacket[:]), rs.BackupMeta.KeyshareServer.Username}
    rpBytes, _ := json.Marshal(rp)
    rs.RedPacketBytes, err = rs.rsaEncrypt(rpBytes)
    return
}

func (rs *recoverySession) aesDecrypt(data []byte) (plaintext []byte, err error) {
    block, err := aes.NewCipher(rs.decryptionKeyBluePacket[:])
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }
    return plaintext, nil
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

func curveDecrypt (ciphertext []byte, privateKey [32]byte) (plain []byte, err error) {
    dummyPrivAuthKey := new([32]byte) // Zero initialized auth key, authentication is not needed
    dummyPubAuthKey := new([32]byte)
    curve25519.ScalarBaseMult(dummyPubAuthKey, dummyPrivAuthKey)

    var decryptNonce [24]byte
    copy(decryptNonce[:], ciphertext[:24])

    plain, ok := box.Open(nil, ciphertext[24:], &decryptNonce, dummyPubAuthKey, &privateKey)
    if !ok {
        return nil, errors.New("Decryption error, was the right key supplied?")
    }
    return plain, nil
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

func  (rs *recoverySession) rsaEncrypt(toEnc []byte) ([]byte, error) {
    rng := rand.Reader
    pub, err := rs.client.loadServerRecoveryPubKey(rs.BackupMeta.KeyshareServer)
    if err != nil {
        panic("Recovery public key could not be found!")
    }

    ciphertext, err := rsa.EncryptPKCS1v15(rng, pub, toEnc)
    if err != nil {
        return nil, err
    }
    return ciphertext, nil
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
        h.RecoveryError(err)
        return
    }

    pin := ""
    var metas []backupMetadata
    for _,kss := range client.keyshareServers{
        var salt [24]byte
        if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
            h.RecoveryError(err)
            return
        }
        pair, err := genKeyPair(phrase[:])
        if err != nil {
            h.RecoveryError(err)
            return
        }

        mnemonic, err := bip39.NewMnemonic(phrase[:])
        if err != nil {
            h.RecoveryError(err)
            return
        }
        h.ShowPhrase(strings.Split(mnemonic, " "))

        kssStore := *kss
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
        if rs.pin == "" {
            // PIN could not be verified
            return
        }
        pin = rs.pin

        // Delete private information from unencrypted metadata
        kssStore.DeviceKey = nil
        kssStore.Nonce = nil
        kssStore.PrivateKey = nil

        rs.BackupMeta.EncRecoveryNonce = rs.BackupMeta.curveEncrypt(salt[:], false)
        status := recoveryInitResponse{}
        err = rs.transport.Post("users/recovery/setup", &status, recoveryInitRequest{
            HashedPin: rs.BackupMeta.HashedPin(pin),
        })
        if err != nil {
            h.RecoveryError(err)
            return
        }
        if status.Status != "success" {
            h.RecoveryError(errors.New("Server error in setup recovery"))
            return
        }
        metas = append(metas, *rs.BackupMeta)
    }
    err := client.storage.StoreRecoveryMetas(metas)
    if err != nil {
    	h.RecoveryError(err)
    	return
	}
	h.RecoveryInitSuccess()
    return
}

func (client *Client) MakeBackup(h recoverySessionHandler) {
    var backups []recoverySession
    metas, err := client.storage.LoadRecoveryMeta()
    if err != nil {
        h.RecoveryError(err)
        return
    }
    for _, meta := range metas {
        b, err := client.storageToBackup(meta.KeyshareServer)
        if err != nil {
        	h.RecoveryError(err)
        	return
		}

        rs := recoverySession{
            BackupMeta:                &meta,
            pin:                       "",
            handler:				   h,
            client:					   client,
        }

        err = rs.serverEncrypt(b)
        if err != nil {
        	h.RecoveryError(err)
        	return
		}
        backups = append(backups, rs)
    }

    b, err := json.Marshal(backups)
    if err != nil {
        h.RecoveryError(err)
    	return
	}

    backup := backups[0].BackupMeta.curveEncrypt(b, false) // The user private key should be the same for all backups
    h.OutputBackup(backup)
}

func (c *Client) StartRecovery(h recoverySessionHandler) {
    log.Println("Getting backup")
    h.GetBackup(func (proceed bool, backup []byte) {
        log.Println("Backup received")
    	if !proceed {
            h.RecoveryError(errors.New("No backup entered"))
            return
        }

        log.Println("Requesting phrase")
        h.RequestPhrase(func (proceed bool, phrase []string) {
            c.decryptAndRecoverBackup(proceed, phrase, h, backup)
        })
	})
}

func (c *Client) decryptAndRecoverBackup(proceed bool, phrase []string, h recoverySessionHandler, backup []byte) {
    log.Println("Phrase received")
    if !proceed {
        return
    }

    phraseBytes, err := bip39.EntropyFromMnemonic(strings.Join(phrase, " "))
    if err != nil {
        h.RecoveryPhraseIncorrect(err)
        h.RequestPhrase(func (proceed bool, phrase []string) {
            c.decryptAndRecoverBackup(proceed, phrase, h, backup)
        })
        return
    }
    key, err := genKeyPair(phraseBytes)
    if err != nil {
        h.RecoveryError(err)
        return
    }

    sessionsBytes, err := curveDecrypt(backup, key.privateKey)
    if err != nil {
        h.RecoveryPhraseIncorrect(err)
        h.RequestPhrase(func (proceed bool, phrase []string) {
            c.decryptAndRecoverBackup(proceed, phrase, h, backup)
        })
        return
    }
    var sessions []recoverySession
    err = json.Unmarshal(sessionsBytes, &sessions)
    if err != nil {
        h.RecoveryError(err)
        return
    }

    if err = c.removeStoredData(); err!=nil {
        h.RecoveryError(err)
        return
    }

    pin := ""
    for _, rs := range sessions {
        rs.transport = irma.NewHTTPTransport(rs.BackupMeta.KeyshareServer.URL)
        rs.client = c
        rs.handler = h
        rs.BackupMeta.UserKeyPair = key

        rs.pin = pin
        rs.VerifyPin(-1, true)
        if rs.pin == "" {
            //PIN could not be verified
            //TODO: Does not revert changes already made when having multiple keyshare servers
            return
        }

        pin = rs.pin
        err := rs.renewDeviceKeys()
        if err != nil {
            h.RecoveryError(err)
            return
        }

        backupBytes, err := rs.aesDecrypt(rs.BluePacketBytes)
        if err != nil {
            h.RecoveryError(err)
            return
        }
        err = c.backupToStorage(backupBytes, rs.BackupMeta.KeyshareServer)
        if err != nil {
            h.RecoveryError(err)
            return
        }
        newClient, err := New(c.storage.storagePath, c.irmaConfigurationPath, c.androidStoragePath, c.handler)
        if err != nil {
            h.RecoveryError(err)
            return
        }
        // TODO: No support yet for multiple keyshare servers, return after the first session
        newMetas := []backupMetadata{*rs.BackupMeta}
        err = newClient.storage.StoreRecoveryMetas(newMetas)
        if err != nil {
            h.RecoveryError(err)
            return
        }
        h.RecoveryPerformed(newClient)
        return
    }
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

func (c *Client) storageToBackup(kss *keyshareServer) (result []byte, err error) {
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
        log.Println("Signatures could not be converted")
        return nil, err
    }
    sigsJson, err := json.Marshal(sigs)
    if err != nil {
    	panic("JSON library produced invalid JSON")
	}

    b := backup{
        Signatures:     sigsJson,
        SecretKey:      c.secretkey,
        Attributes:     selected,
        Paillier:       c.paillierKey(true),
        Logs:           c.logs,
        Preferences:    c.Preferences,
        Updates:        c.updates,
        KeyshareServer: c.keyshareServers[kss.SchemeManagerIdentifier],
    }
    backup, err := json.Marshal(b)
    if err != nil {
        log.Printf("Subset of Attributes could not be marshalled in JSON")
        return nil, err
    }
    return backup, nil
}

func (c *Client) removeStoredData() (err error) {
    // Delete previous files
    files, err := filepath.Glob(c.storage.storagePath + "/*")
    for _, f := range files {
        if !strings.Contains(f, "irma_configuration") {
            err = os.RemoveAll(f)
        }
    }
    if err != nil {
        return
    }

    // Maps are filled on the fly, so need to be emptied first
    c.keyshareServers = make(map[irma.SchemeManagerIdentifier]*keyshareServer)
    c.attributes = make(map[irma.CredentialTypeIdentifier][]*irma.AttributeList)
    return
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

    c.storeSignatures(sigs)
    b.KeyshareServer.Nonce = kss.Nonce
    b.KeyshareServer.DeviceKey = kss.DeviceKey

    c.keyshareServers[kss.SchemeManagerIdentifier] = b.KeyshareServer
    err = c.storage.StoreKeyshareServers(c.keyshareServers)
    err = c.storage.StoreSecretKey(b.SecretKey)
    err = c.storage.StorePreferences(b.Preferences)
    err = c.storage.StorePaillierKeys(b.Paillier)
    err = c.storage.StoreUpdates(b.Updates)
    err = c.storage.StoreLogs(b.Logs)

    for _, a := range b.Attributes {
		a.MetadataAttribute = irma.MetadataFromInt(a.Ints[0], c.storage.Configuration)
        val, ok := c.attributes[a.CredentialType().Identifier()]
        if !ok {
            c.attributes[a.Info().CredentialTypeID] = []*irma.AttributeList{a}
        } else {
            c.attributes[a.Info().CredentialTypeID] = append(val, a)
        }
    }

    err = c.storage.StoreAttributes(c.attributes)
    c, err = New(
		c.storage.storagePath,
		c.irmaConfigurationPath,
		c.androidStoragePath,
		c.handler,
	)
    return err
}

func (c *Client) RecoveryIsConfigured() (bool){
	x, err := c.storage.LoadRecoveryMeta()
	return err == nil && len(x) > 0
}
