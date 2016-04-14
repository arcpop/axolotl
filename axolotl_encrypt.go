package axolotl

import (
	"crypto/cipher"
	"encoding/binary"
	"github.com/arcpop/ecdh"
	"io"
)

func zeroKey(k []byte) {
	if k == nil {
		return
	}
	for i := range k {
		k[i] = 0
	}
}

func dhRatchetGenerateKeys(s *State, randomData io.Reader) error {
	ecdhParams, err := ecdh.GenerateNew(s.dhParams.Curve, randomData)
	if err != nil {
		return err
	}

    nonceSrc := make([]byte, 32)
    _, err = io.ReadFull(randomData, nonceSrc)

	dhSecret, err := ecdhParams.GetSharedSecret(s.dhPublicKey)
	if err != nil {
		return err
	}

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

    

	s.rootKey = rk
    s.headerNonceSource = nonceSrc
	s.hdrKeyS = s.nextHdrKeyS
	s.nextHdrKeyS = nhk
	s.chainKeyS = ck
	s.dhParams = ecdhParams
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
	messageKey := s.hmac(s.chainKeyS).Sum([]byte{0})

	messageCipher, err = s.streamCipher(messageKey)
	if err != nil {
		return nil, err
	}

	m := &message{}

	m.headerNonceSize = byte(headerCipher.NonceSize())
    
    //Generate a nonce based on an initial random secret and the message number,
    //This should not repeat the same nonce for the same header key
    msgNumBuf := make([]byte, 4)
    binary.BigEndian.PutUint32(msgNumBuf[:], s.msgNumS)
	m.headerNonce = make([]byte, m.headerNonceSize)
    copy(m.headerNonce, s.hmac(s.headerNonceSource).Sum(msgNumBuf))

	m.messageNonceSize = byte(messageCipher.NonceSize())
	m.messageNonce = make([]byte, m.messageNonceSize)
	_, err = io.ReadFull(randomData, m.messageNonce)
	if err != nil {
		return nil, err
	}

	//Set the header plaintext
	m.headerData = make([]byte, 8+len(s.dhParams.PublicKey))
	binary.BigEndian.PutUint32(m.headerData[0:4], s.msgNumS)
	binary.BigEndian.PutUint32(m.headerData[4:8], s.prevMsgNumS)
	copy(m.headerData[8:], s.dhParams.PublicKey)

	//Encrypt the header
	m.headerData = headerCipher.Seal(nil, m.headerNonce, m.headerData, []byte{})

	//Encrypt the message
	m.messageData = messageCipher.Seal(nil, m.messageNonce, msg, []byte{})

	m.headerLength = uint32(len(m.headerData))
	m.messageLength = uint32(len(m.messageData))

	s.msgNumS++
	s.chainKeyS = s.hmac(s.chainKeyS).Sum([]byte{1})
	return serialize(m), nil
}
