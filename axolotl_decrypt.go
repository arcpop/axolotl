package axolotl

import (
    "io"
    "container/list"
    "encoding/binary"
	"log"
)

func tryDecrypt(s *State, msg *message, hk, mk key) ([]byte, bool) {
    _, err := tryDecryptHeader(s, hk, msg)
    if err != nil {
        return nil, false
    }
    
    content, err := tryDecryptMessage(s, mk, msg)
    if err != nil {
        return nil, false
    }
    return content, true
}

func tryDecryptWithSkippedKeys(s *State, m *message) ([]byte, bool) {
    var el *list.Element
    var buf[]byte
    var ok = false
    if s.skippedKeys.Len() < 1 {
        return nil, false
    }
    for e := s.skippedKeys.Front(); e != nil; e = e.Next() {
        k := e.Value.(storedkey)
        hk := k[0]
        mk := k[1]
        buf, ok = tryDecrypt(s, m, hk, mk)
        if ok {
            el = e
            break
        }
    }
    if ok {
        s.skippedKeys.Remove(el)
        return buf, ok
    }
    return nil, false
}


func tryDecryptHeader(s * State, hk key, msg *message) ([]byte, error) {
    if len(hk) == 0 {
        return nil, ErrInvalidKeyLength
    }
    headerCipher, err := s.streamCipher(hk)
    if err != nil {
        return nil, err
    }
    
    return headerCipher.Open(nil, msg.headerNonce, msg.headerData, nil)
}

func tryDecryptMessage(s *State, mk key, msg *message) ([]byte, error) {
    if len(mk) == 0 {
        return nil, ErrInvalidKeyLength
    }
    msgCipher, err := s.streamCipher(mk)
    if err != nil {
        return nil, err
    }
    return msgCipher.Open(nil, msg.messageNonce, msg.messageData, nil)
}
func axolotlDecryptMessageBuffer(s *State, b []byte) ([]byte, error) {
    m, err := deserialize(b)
    
    if err != nil {
        return nil, err
    }
    return decryptInner(s, m)
}

func axolotlDecryptMessage(s *State, rd io.Reader) ([]byte, error) {
    m, err := deserializeFromReader(rd)
    
    if err != nil {
        return nil, err
    }
    return decryptInner(s, m)
}
func decryptInner(s *State, m *message) ([]byte, error) {
    var err error
    msg, ok := tryDecryptWithSkippedKeys(s, m)
    if ok {
        return msg, nil
    }
    
    var hdr []byte
    
    if hdr, err = tryDecryptHeader(s, s.hdrKeyR, m); err == nil {
        np := binary.BigEndian.Uint32(hdr[0:4])
        ckp, mk := stageSkippedHeaderAndMessageKeys(s, s.hdrKeyR, s.msgNumR, np, s.chainKeyR)
        if ckp != nil && mk != nil {
            msg, err = tryDecryptMessage(s, mk, m)
            if err != nil {
                return nil, err
            }
            commitStagedSkippedKeys(s)
            s.msgNumR = np + 1
            s.chainKeyR = ckp
            return msg, nil
        }
        return nil, ErrUndecryptable
    } 
    //else
    if hdr, err = tryDecryptHeader(s, s.nextHdrKeyR, m); err != nil || s.ratchetFlag {
        return nil, ErrUndecryptable
    }
    
    np := binary.BigEndian.Uint32(hdr[0:4])
    pnp := binary.BigEndian.Uint32(hdr[4:8])
    dhrp := hdr[8:]
    
    
    stageSkippedHeaderAndMessageKeys(s, s.hdrKeyR, s.msgNumR, pnp, s.chainKeyR)
    hkp := s.nextHdrKeyR
    
    dhSecret, err := s.dhParams.GetSharedSecret(dhrp)
    if err != nil {
        return nil, ErrMalformedMessage
    }
    
    hm := s.hmac(s.rootKey).Sum(dhSecret)
    kdf := s.hkdf(hm, nil, nil)
    
    rkp := make([]byte, 32)
    nhkp := make([]byte, 32)
    ckp := make([]byte, 32)
    
    _, err = io.ReadFull(kdf, rkp)
    if err != nil { //This will never happen, we only pull 3 * 32 bytes from the kdf
        log.Fatal(err)
    }
    _, err = io.ReadFull(kdf, nhkp)
    if err != nil { //This will never happen, we only pull 3 * 32 bytes from the kdf
        log.Fatal(err)
    }
    _, err = io.ReadFull(kdf, ckp)
    if err != nil { //This will never happen, we only pull 3 * 32 bytes from the kdf
        log.Fatal(err)
    }
    var mk key
    ckp, mk = stageSkippedHeaderAndMessageKeys(s, hkp, 0, np, ckp)
    if msg, err = tryDecryptMessage(s, mk, m); err != nil {
        //Should we rather pass ErrUndecryptable here?
        return nil, err 
    }
    s.rootKey = rkp
    s.hdrKeyR = hkp
    s.nextHdrKeyR = nhkp
    s.dhPublicKey = dhrp
    zeroKey(s.dhParams.PrivateKey)
    s.ratchetFlag = true
    commitStagedSkippedKeys(s)
    s.msgNumR = np + 1
    s.chainKeyR = ckp
    return msg, nil
}

func commitStagedSkippedKeys(s *State) {
    for _, k := range s.stagedSkippedMKs {
        s.skippedKeys.PushBack(k)
    }
    s.stagedSkippedMKs = s.stagedSkippedMKs[:0]
}
func stageSkippedHeaderAndMessageKeys(s *State, hkr key, nr, np uint32, ckr key) (key, key) {
    if len(ckr) == 0 {
        return nil, nil
    }
    
    if cap(s.stagedSkippedMKs) == 0 {
        s.stagedSkippedMKs = make([]storedkey, 0, np)
    }
    var mk key
    for i := nr; i <= np; i++ {
        mk = s.hmac(ckr).Sum([]byte{ 0, })
        ckr = s.hmac(ckr).Sum([]byte{ 1, })
        s.stagedSkippedMKs = append(s.stagedSkippedMKs, [2]key{hkr, mk})
    }
    return ckr, mk
}