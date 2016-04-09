package axolotl

import (
	"errors"
	"crypto/elliptic"
	"hash"
	"io"
	"crypto/cipher"
	"crypto/rand"
	"container/list"
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
    HKDF_SHA_256 = iota
    HKDF_SHA_384 = iota
    HKDF_SHA_512 = iota
    HKDF_SHA3_256 = iota
    HKDF_SHA3_384 = iota
    HKDF_SHA3_512 = iota
)

//Specified which hash function is used for HMAC
const (
    HMAC_SHA_256 = iota
    HMAC_SHA_384 = iota
    HMAC_SHA_512 = iota
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
    CurveParam uint8
    StreamCipher uint8
    HKDF uint8
    HMAC uint8
    SenderSide bool
    
    rootKey key
    
    hdrKeyS key
    hdrKeyR key
    
    nextHdrKeyS key
    nextHdrKeyR key
    
    chainKeyS key
    chainKeyR key
    
    dhRatchetS dhkey
    dhRatchetR dhkey
    
    dhRatchetPrivKey dhkey
    
    msgNumS uint32
    msgNumR uint32
    
    prevMsgNumS uint32
    
    ratchetFlag bool
    
    skippedKeys *list.List
    
    stagedSkippedMKs []storedkey
    
    curve elliptic.Curve
    hmac func(key []byte) hash.Hash
    hkdf func (secret, salt, info []byte) io.Reader
    streamCipher func(key []byte) (cipher.AEAD, error)
}

//New returns a new state to work with the axolotl protocol
func New(curveParam, streamCipher, HKDF, HMAC uint8, senderSide bool, masterKey, initialDHRatchetKey, privateDHRatchetKey []byte) (*State, error)  {
    return axolotlNew(curveParam, streamCipher, HKDF, HMAC, senderSide, masterKey, initialDHRatchetKey, privateDHRatchetKey)
}
/*
//FromFile returns a previous saved state from file to work with the axolotl protocol
func FromFile(fileName string) (*State, error)  {
    return axolotlFromFile(fileName)
}

//SaveTo saves the current state into the file specified by fileName
func (s *State) SaveTo(fileName string) (error) {
    return axolotlSaveTo(s, fileName)
}
*/
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

//NewP521_SHA512_AESGCM256 returns axolotl with max security
func NewP521_SHA512_AESGCM256(senderSide bool, masterKey, initialDHRatchetKey, privateDHRatchetKey []byte) (*State, error){
    return New(CurveP521, AES_GCM_256, HKDF_SHA_512, HMAC_SHA_512, senderSide, masterKey, initialDHRatchetKey, privateDHRatchetKey)
}
