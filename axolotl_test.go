package axolotl_test

import (
    "testing"
    "github.com/arcpop/axolotl"
	"crypto/rand"
    "crypto/elliptic"
    "io"
)


func TestAxolotl(t *testing.T)  {
    mk := make([]byte, 32)
    io.ReadFull(rand.Reader, mk)
    c := elliptic.P256()
    priv, x, y, err:= elliptic.GenerateKey(c, rand.Reader)
    
    if err != nil {
        t.Fatal(err)
    }
    pub := elliptic.Marshal(c, x, y)
    
    Alice, errA := axolotl.New(axolotl.CurveP256, axolotl.GCM_AES_256, axolotl.HKDF_SHA_256, axolotl.HMAC_SHA_256, true, mk, pub, nil)
    Bob, errB := axolotl.New(axolotl.CurveP256, axolotl.GCM_AES_256, axolotl.HKDF_SHA_256, axolotl.HMAC_SHA_256, false, mk, pub, priv)
    
    
    if errA != nil {
        t.Fatal(errA)
    }
    if errB != nil {
        t.Fatal(errB)
    }

    msg, err := Alice.EncryptMessage([]byte("Hello World!"))
    if err != nil {
        t.Fatal(err)
    }

    decmsg, err := Bob.DecryptMessageBuffer(msg)
    if err != nil {
        t.Fatal(err)
    }
    
    t.Log(string(decmsg))
    
    if string(decmsg) != "Hello World!" {
        t.Fatal(err)
    }
    
    msg2, err := Alice.EncryptMessage([]byte("MSG2"))
    if err != nil {
        t.Fatal(err)
    }
    msg3, err := Alice.EncryptMessage([]byte("MSG3"))
    if err != nil {
        t.Fatal(err)
    }
    decmsg, err = Bob.DecryptMessageBuffer(msg2)
    if err != nil {
        t.Fatal(err)
    }
    if string(decmsg) != "MSG2" {
        t.Fatal(err)
    }
    decmsg, err = Bob.DecryptMessageBuffer(msg3)
    if err != nil {
        t.Fatal(err)
    }
    if string(decmsg) != "MSG3" {
        t.Fatal(err)
    }
    bobmsg1, err := Bob.EncryptMessage([]byte("Bob"))
    if err != nil {
        t.Fatal(err)
    }
    decmsg, err = Alice.DecryptMessageBuffer(bobmsg1)
    if err != nil {
        t.Fatal(err)
    }
    if string(decmsg) != "Bob" {
        t.Fatal(err)
    }
    
    msg4, err := Alice.EncryptMessage([]byte("MSG4"))
    if err != nil {
        t.Fatal(err)
    }
    decmsg, err = Bob.DecryptMessageBuffer(msg4)
    if err != nil {
        t.Fatal(err)
    }
    if string(decmsg) != "MSG4" {
        t.Fatal(err)
    }
    
    
}