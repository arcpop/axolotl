package axolotl

import (
	"io"
    "container/list"
)

func axolotlNew(curveParam, streamCipher, HKDF, HMAC uint8, senderSide bool, masterKey[]byte, initialDHRatchetKey []byte) (*State, error)  {
    state := &State{ 
        CurveParam: curveParam, 
        StreamCipher: streamCipher, 
        HKDF: HKDF, HMAC: HMAC, 
        SenderSide: senderSide,
        curve: dhCurves[curveParam](),
        streamCipher: streamCiphers[streamCipher],
        hkdf: hkdfs[HKDF],
        hmac: hmacs[HMAC],
        ratchetFlag: senderSide,
        skippedKeys: list.New(),
    }
    kdf := state.hkdf(masterKey, []byte{}, []byte{})
    
    state.rootKey = make([]byte, 32)
    _, err := io.ReadFull(kdf, state.rootKey)
    if err != nil {
        return nil, err
    }
    
    if senderSide {
        state.dhRatchetR = initialDHRatchetKey
        err = createSenderKeys(kdf, state)
    } else {
        state.dhRatchetS = initialDHRatchetKey
        err = createReceiverKeys(kdf, state)
    }
    if err != nil {
        return nil, err
    }
    return state, nil
}


func createSenderKeys(kdf io.Reader, state *State) (error) {
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

func createReceiverKeys(kdf io.Reader, state *State) (error) {
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
