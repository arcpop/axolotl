package axolotl

import (
	"crypto/cipher"
	"io"
	"encoding/binary"
	"crypto/elliptic"
)

func zeroKey(k []byte) {
    if k == nil {
        return
    }
    for i := range k {
        k[i] = 0
    }
}

func dhRatchetGenerateKeys(s * State, randomData io.Reader) (error) {
    priv, x, y, err := elliptic.GenerateKey(s.curve, randomData)
    if err != nil {
        return err
    }
    pub := elliptic.Marshal(s.curve, x, y)
    rx, ry := elliptic.Unmarshal(s.curve, s.dhRatchetR)
    sx, sy := s.curve.ScalarMult(rx, ry, priv)
    dhSecret := elliptic.Marshal(s.curve, sx, sy)
    
    //kdf := KDF( HMAC-HASH(RK, DH(DHRs, DHRr)) )
    kdf := s.hkdf(s.hmac(s.rootKey).Sum(dhSecret), []byte{}, []byte{})
    
    rk := make([]byte, 32)
    _, err = io.ReadFull(kdf, rk)
    if err != nil {
        return err
    }
    
    nhk := make([]byte, 32)
    _, err = io.ReadFull(kdf, nhk)
    if err != nil {
        return err
    }
    
    ck := make([]byte, 32)
    _, err = io.ReadFull(kdf, ck)
    if err != nil {
        return err
    }
    
    copy(s.rootKey, rk)
    copy(s.nextHdrKeyS, nhk)
    copy(s.chainKeyS, ck)
    
    zeroKey(s.dhRatchetPrivKey)
    s.dhRatchetPrivKey = make([]byte, len(priv))
    copy(s.dhRatchetPrivKey, priv)
    zeroKey(priv)
    
    
    s.dhRatchetS = make([]byte, len(pub))
    copy(s.dhRatchetS, pub)
    
    s.prevMsgNumS = s.msgNumS
    s.msgNumS = 0
    s.ratchetFlag = false
    
    return nil
}

func axolotlEncryptMessage(s *State, msg []byte, randomData io.Reader) ([]byte, error) {
    var err error
    var headerCipher cipher.AEAD
    var messageCipher cipher.AEAD
    
    if s.ratchetFlag {
        err = dhRatchetGenerateKeys(s, randomData)
        if err != nil {
            return nil, err
        }
    }
    
    headerCipher, err = s.streamCipher(s.hdrKeyS)
    if err != nil {
        return nil, err
    }
    
    messageKey := s.hmac(s.chainKeyS).Sum([]byte("0"))
    
    headerCipher, err = s.streamCipher(messageKey)
    if err != nil {
        return nil, err
    }
    
    m := &message{}
    
    m.headerNonceSize = headerCipher.NonceSize()
    m.headerNonce = make([]byte, m.headerNonceSize)
    _, err = io.ReadFull(randomData, m.headerNonce)
    if err != nil {
        return nil, err
    }
    
    m.messageNonceSize = messageCipher.NonceSize()
    m.messageNonce = make([]byte, m.messageNonceSize)
    _, err = io.ReadFull(randomData, m.messageNonce)
    if err != nil {
        return nil, err
    }
    
    //Set the header plaintext
    m.headerData = make([]byte, 0, 8 + len(s.dhRatchetS))
    binary.BigEndian.PutUint32(m.headerData[0:4], s.msgNumS)
    binary.BigEndian.PutUint32(m.headerData[4:8], s.prevMsgNumS)
    copy(m.headerData[8:], s.dhRatchetS)
    
    //Encrypt the header
    m.headerData = headerCipher.Seal(nil, m.headerNonce, m.headerData, []byte{})
    
    //Encrypt the message
    m.messageData = messageCipher.Seal(nil, m.messageNonce, msg, []byte{})
    
    m.headerLength = len(m.headerData)
    m.messageLength = len(m.messageData)
    
    s.msgNumS++
    s.chainKeyS = s.hmac(s.chainKeyS).Sum([]byte("1"))
    return serialize(m), nil
}