package axolotl_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/arcpop/axolotl"
	"github.com/arcpop/ecdh"
	"io"
	"testing"
)

var messagesFromAlice = []string{
	"Alice1",
	"Alice2",
	"Alice3",
	"Alice4",
	"Alice5",
	"Alice6",
	"Alice7",
	"Alice8",
	"Alice9",
	"Alice0",
}

var messagesFromBob = []string{
	"Bob1",
	"Bob2",
	"Bob3",
	"Bob4",
	"Bob5",
	"Bob6",
	"Bob7",
	"Bob8",
	"Bob9",
	"Bob0",
}

var ctFromAlice [][]byte
var ctFromBob [][]byte
var aliceEncMessageNumber = 0
var aliceDecMessageNumber = 0
var bobEncMessageNumber = 0
var bobDecMessageNumber = 0

func aliceEnc(t *testing.T, s *axolotl.State) {
	ct, err := s.EncryptMessage([]byte(messagesFromAlice[aliceEncMessageNumber]))
	if err != nil {
		t.Fatal(err)
	}
	ctFromAlice = append(ctFromAlice, ct)
	aliceEncMessageNumber++
}
func bobEnc(t *testing.T, s *axolotl.State) {
	ct, err := s.EncryptMessage([]byte(messagesFromBob[bobEncMessageNumber]))
	if err != nil {
		t.Fatal(err)
	}
	ctFromBob = append(ctFromBob, ct)
	bobEncMessageNumber++
}
func aliceDec(t *testing.T, s *axolotl.State) {
	for i := aliceDecMessageNumber; i < bobEncMessageNumber; i++ {
		pt, err := s.DecryptMessageBuffer(ctFromBob[i])
		if err != nil {
			t.Fatal(err)
		}
		if string(pt) != messagesFromBob[i] {
			t.Fatal(string(pt), "!=", messagesFromBob[i])
		}
	}
	aliceDecMessageNumber = bobEncMessageNumber
}
func bobDec(t *testing.T, s *axolotl.State) {
	for i := bobDecMessageNumber; i < aliceEncMessageNumber; i++ {
		pt, err := s.DecryptMessageBuffer(ctFromAlice[i])
		if err != nil {
			t.Fatal(err)
		}
		if string(pt) != messagesFromAlice[i] {
			t.Fatal(string(pt), "!=", messagesFromAlice[i])
		}
	}
	bobDecMessageNumber = aliceEncMessageNumber
}

func TestAxolotl(t *testing.T) {
	mk := make([]byte, 32)
	io.ReadFull(rand.Reader, mk)
	dhParams, err := ecdh.GenerateNew(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	Alice, err := axolotl.NewP521_SHA512_AESGCM256_Sender(mk, dhParams.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	Bob, err := axolotl.NewP521_SHA512_AESGCM256_Receiver(mk, dhParams)
	if err != nil {
		t.Fatal(err)
	}

	aliceEnc(t, Alice)
	bobDec(t, Bob)
	bobEnc(t, Bob)
	aliceEnc(t, Alice)
	bobDec(t, Bob)
	bobEnc(t, Bob)
	aliceDec(t, Alice)
	bobEnc(t, Bob)
	aliceDec(t, Alice)
	aliceEnc(t, Alice)
	aliceDec(t, Alice)
	aliceEnc(t, Alice)
	bobDec(t, Bob)
	bobDec(t, Bob)
}
