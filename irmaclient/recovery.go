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
    handler                   recoverySessionHandler
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
    RecoveryPinOk()
    RecoveryBlocked(duration int)
    RecoveryError(err error)
}

type PhraseHandler func(proceed bool, phrase []string)

type recoveryRequest struct {
    Delta           string			`json:"delta"`
}

type recoveryInitRequest struct {
    HashedPin		string			`json:"hashedPin"`
}

type recoveryInitResponse struct {
    Status  string   `json:"status"`
    Message string   `json:"message"`
}

type recoveryServerKeyResponse struct {
    Key     [32]byte `json:"serverKey"`
}

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
    if rs.BackupMeta.RecoveryNonce == nil {
        rs.BackupMeta.RecoveryNonce = rs.BackupMeta.KeyshareServer.Nonce
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

func (rs *recoverySession) storeBackup(bluePacket []byte) {
    // TODO Implement
}

func (rs *recoverySession) renewDeviceKeys() (err error) {
    delta, err := gabi.RandomBigInt(128)
	if err != nil {
        return
    }
    rr := recoveryRequest{delta.String()}
    rs.recoveryServerKeyResponse = &recoveryServerKeyResponse{}
    rs.transport.Post("users/recovery/new-device", rs.recoveryServerKeyResponse, rr)
    rs.BackupMeta.KeyshareServer.DeviceKey.Key = delta
    m, err := rs.storage.LoadKeyshareServers()
    if err != nil{
        return err
    }
    m[rs.BackupMeta.KeyshareServer.SchemeManagerIdentifier] = rs.BackupMeta.KeyshareServer
    rs.storage.StoreKeyshareServers(m)

    return nil

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

        rs := recoverySession{
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
            handler:				   h,
        }

        rs.VerifyPin(-1, false)
        pin = rs.pin

        rs.BackupMeta.RecoveryNonce = salt[:]
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
    var backups []*recoverySession
    metas, err := client.storage.LoadRecoveryMeta()
    if err != nil {
        return
    }
    for _, meta := range metas {
        b := client.storageToBackup(meta.KeyshareServer)
        //b = meta.curveEncrypt(b, false)
        rs := recoverySession{
            BackupMeta:                &meta,
            pin:                       "",
            handler:				   h,
        }
        //rs.serverEncrypt(b)
        rs.BluePacketBytes = b
        backups = append(backups, &rs)
    }
    client.storage.store(*backups[0], "backup")
    return nil
}

func (c *Client) StartRecovery(handler recoverySessionHandler) {
    pin := ""
    var rs recoverySession
    c.storage.load(&rs, "backup")
    // TODO: Add support multiple keyshare servers
    //for _, rs := range sessions {
        rs.transport = irma.NewHTTPTransport(rs.BackupMeta.KeyshareServer.URL)
        rs.storage = &c.storage
        rs.handler = handler
        rs.pin = pin

        rs.VerifyPin(-1, true)
        pin = rs.pin
        rs.renewDeviceKeys()
        c.backupToStorage(rs.BluePacketBytes, rs.BackupMeta.KeyshareServer)

        //rs.decryptionKeyBluePacket = resp.Key
        //rs.BluePacketBytes = rs.aesDecrypt(rs.RedPacketBytes)
        //backup := rs.backupMeta.curveDecrypt(rs.bluePacketBytes)

    //}
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
	os.Mkdir(c.storage.path("sigs"), 0755)
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
            if attr.Info().SchemeManagerID == kss.SchemeManagerIdentifier { // Assumption: one kss per scheme
                // Skip attributes that do not belong to keyshareserver kss
                selected = append(selected, attr)
                signatureFiles = append(signatureFiles, c.storage.signatureFilename(attr))
            }
        }
    }
    sigs, err := c.getSignatures(signatureFiles) // TODO Add error handling
    if err != nil {
        panic("Signatures could not be converted")
    }
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
