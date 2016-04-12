package axolotl

import (
	"container/list"
	"github.com/arcpop/ecdh"
	"io"
)

func axolotlNewS(curveParam, streamCipher, HKDF, HMAC uint8, masterKey, dhPubKey []byte) (*State, error) {
	state := &State{
		CurveParam:   curveParam,
		StreamCipher: streamCipher,
		HKDF:         HKDF, HMAC: HMAC,
		dhParams:     &ecdh.ECDH{Curve: dhCurves[curveParam]()},
		dhPublicKey:  dhPubKey,
		streamCipher: streamCiphers[streamCipher],
		hkdf:         hkdfs[HKDF],
		hmac:         hmacs[HMAC],
		SenderSide:   true,
		ratchetFlag:  true,
		skippedKeys:  list.New(),
	}
	kdf := state.hkdf(masterKey, []byte{}, []byte{})

	state.rootKey = make([]byte, 32)
	_, err := io.ReadFull(kdf, state.rootKey)
	if err != nil {
		return nil, err
	}

	err = createSenderKeys(kdf, state)
	if err != nil {
		return nil, err
	}
	return state, nil
}

func axolotlNewR(curveParam, streamCipher, HKDF, HMAC uint8, masterKey []byte, ecdhParams *ecdh.ECDH) (*State, error) {
	state := &State{
		CurveParam:   curveParam,
		StreamCipher: streamCipher,
		HKDF:         HKDF, HMAC: HMAC,
		dhParams:     ecdhParams,
		dhPublicKey:  nil,
		streamCipher: streamCiphers[streamCipher],
		hkdf:         hkdfs[HKDF],
		hmac:         hmacs[HMAC],
		SenderSide:   false,
		ratchetFlag:  false,
		skippedKeys:  list.New(),
	}
	kdf := state.hkdf(masterKey, []byte{}, []byte{})

	state.rootKey = make([]byte, 32)
	_, err := io.ReadFull(kdf, state.rootKey)
	if err != nil {
		return nil, err
	}

	err = createReceiverKeys(kdf, state)
	if err != nil {
		return nil, err
	}
	return state, nil
}

func createSenderKeys(kdf io.Reader, state *State) error {
	state.hdrKeyR = make([]byte, 32)
	_, err := io.ReadFull(kdf, state.hdrKeyR)
	if err != nil {
		return err
	}

	state.nextHdrKeyS = make([]byte, 32)
	_, err = io.ReadFull(kdf, state.nextHdrKeyS)
	if err != nil {
		return err
	}

	state.nextHdrKeyR = make([]byte, 32)
	_, err = io.ReadFull(kdf, state.nextHdrKeyR)
	if err != nil {
		return err
	}

	state.chainKeyR = make([]byte, 32)
	_, err = io.ReadFull(kdf, state.chainKeyR)
	if err != nil {
		return err
	}

	return nil
}

func createReceiverKeys(kdf io.Reader, state *State) error {
	state.hdrKeyS = make([]byte, 32)
	_, err := io.ReadFull(kdf, state.hdrKeyS)
	if err != nil {
		return err
	}

	state.nextHdrKeyR = make([]byte, 32)
	_, err = io.ReadFull(kdf, state.nextHdrKeyR)
	if err != nil {
		return err
	}

	state.nextHdrKeyS = make([]byte, 32)
	_, err = io.ReadFull(kdf, state.nextHdrKeyS)
	if err != nil {
		return err
	}

	state.chainKeyS = make([]byte, 32)
	_, err = io.ReadFull(kdf, state.chainKeyS)
	if err != nil {
		return err
	}

	return nil
}
