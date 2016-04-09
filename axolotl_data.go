package axolotl

import (
	"crypto/cipher"
	"crypto/aes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
    "golang.org/x/crypto/sha3"
    "golang.org/x/crypto/hkdf"
    "io"
)


type key []byte
type dhkey []byte
type storedkey [2]key


var streamCiphers = map[uint8]func([]byte) (cipher.AEAD, error) {
    AES_GCM_128: func (key []byte) (cipher.AEAD, error) {
        if len(key) < 16 {
            return nil, ErrInvalidKeyLength
        }
        c, err := aes.NewCipher(key[0:16])
        if err != nil {
            return nil, err
        }
        return cipher.NewGCM(c)
    },
    AES_GCM_192: func (key []byte) (cipher.AEAD, error) {
        if len(key) < 24 {
            return nil, ErrInvalidKeyLength
        }
        c, err := aes.NewCipher(key[0:24])
        if err != nil {
            return nil, err
        }
        return cipher.NewGCM(c)
    },
    AES_GCM_256: func (key []byte) (cipher.AEAD, error) {
        if len(key) < 32 {
            return nil, ErrInvalidKeyLength
        }
        c, err := aes.NewCipher(key[0:32])
        if err != nil {
            return nil, err
        }
        return cipher.NewGCM(c)
    },
}

var dhCurves = map[uint8]func() elliptic.Curve {
    CurveP224: elliptic.P224,
    CurveP256: elliptic.P256,
    CurveP384: elliptic.P384,
    CurveP521: elliptic.P521,
}

var hmacs = map[uint8]func([]byte) hash.Hash {
    HMAC_SHA_256: func(key []byte) hash.Hash { return hmac.New(sha256.New, key) },
    HMAC_SHA_384: func(key []byte) hash.Hash { return hmac.New(sha512.New384, key) },
    HMAC_SHA_512: func(key []byte) hash.Hash { return hmac.New(sha256.New, key) },
    HMAC_SHA3_256: func(key []byte) hash.Hash { return hmac.New(sha3.New256, key) },
    HMAC_SHA3_384: func(key []byte) hash.Hash { return hmac.New(sha3.New384, key) },
    HMAC_SHA3_512: func(key []byte) hash.Hash { return hmac.New(sha3.New512, key) },
}

var hkdfs = map[uint8]func ([]byte, []byte, []byte) io.Reader {
    HKDF_SHA_256: func(secret, salt, info []byte) io.Reader { return hkdf.New(sha256.New, secret, salt, info) },
    HKDF_SHA_384: func(secret, salt, info []byte) io.Reader { return hkdf.New(sha512.New384, secret, salt, info) },
    HKDF_SHA_512: func(secret, salt, info []byte) io.Reader { return hkdf.New(sha256.New, secret, salt, info) },
    HKDF_SHA3_256: func(secret, salt, info []byte) io.Reader { return hkdf.New(sha3.New256, secret, salt, info) },
    HKDF_SHA3_384: func(secret, salt, info []byte) io.Reader { return hkdf.New(sha3.New384, secret, salt, info) },
    HKDF_SHA3_512: func(secret, salt, info []byte) io.Reader { return hkdf.New(sha3.New512, secret, salt, info) },
}


