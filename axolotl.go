package axolotl

import (
	"container/list"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"github.com/arcpop/ecdh"
	"hash"
	"io"
)

//Specifies which elliptic curve is used for ECDH
const (
	CurveP224 = iota
	CurveP256 = iota
	CurveP384 = iota
	CurveP521 = iota
)

//Specifies which stream cipher is used for symmetric en-/decryption
const (
	AES_GCM_128 = iota
	AES_GCM_192 = iota
	AES_GCM_256 = iota
)

//Specifies which hashed key derivation function is used to generate the keystream
const (
	HKDF_SHA_256  = iota
	HKDF_SHA_384  = iota
	HKDF_SHA_512  = iota
	HKDF_SHA3_256 = iota
	HKDF_SHA3_384 = iota
	HKDF_SHA3_512 = iota
)

//Specified which hash function is used for HMAC
const (
	HMAC_SHA_256  = iota
	HMAC_SHA_384  = iota
	HMAC_SHA_512  = iota
	HMAC_SHA3_256 = iota
	HMAC_SHA3_384 = iota
	HMAC_SHA3_512 = iota
)

//ErrInvalidKeyLength gets returned if a function expecting a key gets a key which is too short
var ErrInvalidKeyLength = errors.New("The specified key has not sufficient length.")

var ErrMalformedMessage = errors.New("The passed message seem to be malformed.")

var ErrUndecryptable = errors.New("The passed message cannot be decrypted.")

//State describes an axolotl protocol state
type State struct {
	CurveParam   uint8
	StreamCipher uint8
	HKDF         uint8
	HMAC         uint8
	SenderSide   bool

	rootKey key

	hdrKeyS key
	hdrKeyR key

	nextHdrKeyS key
	nextHdrKeyR key

	chainKeyS key
	chainKeyR key

	dhParams    *ecdh.ECDH
	dhPublicKey dhkey

	msgNumS uint32
	msgNumR uint32

	prevMsgNumS uint32

	ratchetFlag bool

	skippedKeys *list.List

	stagedSkippedMKs []storedkey

	hmac         func(key []byte) hash.Hash
	hkdf         func(secret, salt, info []byte) io.Reader
	streamCipher func(key []byte) (cipher.AEAD, error)
}

//NewSender returns a new state to work with the axolotl protocol
func NewSender(curveParam, streamCipher, HKDF, HMAC uint8, masterKey, dhPubKey []byte) (*State, error) {
	return axolotlNewS(curveParam, streamCipher, HKDF, HMAC, masterKey, dhPubKey)
}

//NewReceiver returns a new state to work with the axolotl protocol
func NewReceiver(curveParam, streamCipher, HKDF, HMAC uint8, masterKey []byte, ecdhParams *ecdh.ECDH) (*State, error) {
	return axolotlNewR(curveParam, streamCipher, HKDF, HMAC, masterKey, ecdhParams)
}

//FromFile returns a previous saved state from file to work with the axolotl protocol
func FromFile(fileName string) (*State, error) {
	return axolotlFromFile(fileName)
}

//SaveTo saves the current state into the file specified by fileName
func (s *State) SaveTo(fileName string) error {
	return axolotlSaveTo(s, fileName)
}

//DecryptMessage decrypts the message
func (s *State) DecryptMessage(rd io.Reader) ([]byte, error) {
	return axolotlDecryptMessage(s, rd)
}

//DecryptMessageBuffer decrypts the message
func (s *State) DecryptMessageBuffer(b []byte) ([]byte, error) {
	return axolotlDecryptMessageBuffer(s, b)
}

//EncryptMessage encrypts the message
func (s *State) EncryptMessage(message []byte) ([]byte, error) {
	return axolotlEncryptMessage(s, message, rand.Reader)
}

//NewP521_SHA512_AESGCM256_Sender returns axolotl with max security
func NewP521_SHA512_AESGCM256_Sender(masterKey, dhPublicKey []byte) (*State, error) {
	return NewSender(CurveP521, AES_GCM_256, HKDF_SHA_512, HMAC_SHA_512, masterKey, dhPublicKey)
}

//NewP521_SHA512_AESGCM256_Receiver returns axolotl with max security
func NewP521_SHA512_AESGCM256_Receiver(masterKey []byte, dhParams *ecdh.ECDH) (*State, error) {
	return NewReceiver(CurveP521, AES_GCM_256, HKDF_SHA_512, HMAC_SHA_512, masterKey, dhParams)
}
