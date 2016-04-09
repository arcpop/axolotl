package axolotl

import (
	"errors"
	"crypto/elliptic"
	"hash"
	"io"
	"crypto/cipher"
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
    GCM_AES_128 = iota
    GCM_AES_192 = iota
    GCM_AES_256 = iota
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
    
    msgNumS uint32
    msgNumR uint32
    
    ratchetFlag bool
    
    skippedKeys []storedkey
    
    curve elliptic.Curve
    hmac func(key []byte) hash.Hash
    hkdf func (secret, salt, info []byte) io.Reader
    streamCipher func(key []byte) (cipher.AEAD, error)
}

//New returns a new state to work with the axolotl protocol
func New(curveParam, streamCipher, HKDF, HMAC uint8, senderSide bool, masterKey[]byte, initialDHRatchetKey []byte) (*State, error)  {
    return axolotlNew(curveParam, streamCipher, HKDF, HMAC, senderSide, masterKey, initialDHRatchetKey)
}

//FromFile returns a previous saved state from file to work with the axolotl protocol
func FromFile(fileName string) (*State, error)  {
    return axolotlFromFile(fileName)
}

//SaveTo saves the current state into the file specified by fileName
func (s *State) SaveTo(fileName string) (error) {
    return axolotlSaveTo(s, fileName)
}

//DecryptMessage decrypts the message
func (s *State) DecryptMessage(rd io.Reader) ([]byte, error) {
    return axolotlDecryptMessage(rd, message)
}

//EncryptMessage encrypts the message
func (s *AxolotlState) EncryptMessage(message []byte) ([]byte, error) {
    return axolotlEncryptMessage(message)
}
