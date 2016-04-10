package axolotl

import (
	"os"
    "io"
    "encoding/binary"
    "container/list"
	"github.com/arcpop/ecdh"
)



func axolotlFromFile(fileName string) (*State, error)  {
    f, err := os.Open(fileName)
    if err != nil {
        return nil, err
    }
    defer f.Close()
    
    var buf [32]byte
    s := &State{}
    _, err = io.ReadFull(f, buf[0:18])
    if err != nil {
        return nil, err
    }
    
    s.CurveParam = buf[0]
    s.StreamCipher = buf[1]
    s.HKDF = buf[2]
    s.HMAC = buf[3]
    s.SenderSide = buf[5] != 0
    s.ratchetFlag = buf[6] != 0
    s.msgNumS = binary.BigEndian.Uint32(buf[6:10])
    s.msgNumR = binary.BigEndian.Uint32(buf[10:14])
    s.prevMsgNumS = binary.BigEndian.Uint32(buf[14:18])
    
    s.rootKey = make(key, 32)
    _, err = io.ReadFull(f, s.rootKey)
    if err != nil {
        return nil, err
    }
    s.hdrKeyS = make(key, 32)
    _, err = io.ReadFull(f, s.hdrKeyS)
    if err != nil {
        return nil, err
    }
    s.hdrKeyR = make(key, 32)
    _, err = io.ReadFull(f, s.hdrKeyR)
    if err != nil {
        return nil, err
    }
    s.nextHdrKeyS = make(key, 32)
    _, err = io.ReadFull(f, s.nextHdrKeyS)
    if err != nil {
        return nil, err
    }
    s.nextHdrKeyR = make(key, 32)
    _, err = io.ReadFull(f, s.nextHdrKeyR)
    if err != nil {
        return nil, err
    }
    s.chainKeyS = make(key, 32)
    _, err = io.ReadFull(f, s.chainKeyS)
    if err != nil {
        return nil, err
    }
    s.chainKeyR = make(key, 32)
    _, err = io.ReadFull(f, s.chainKeyR)
    if err != nil {
        return nil, err
    }
    _, err = io.ReadFull(f, buf[0:12])
    if err != nil {
        return nil, err
    }
    dhrsLen := binary.BigEndian.Uint32(buf[0:4])
    dhrrLen := binary.BigEndian.Uint32(buf[4:8])
    dhrpLen := binary.BigEndian.Uint32(buf[8:12])
    s.dhParams = &ecdh.ECDH{Curve: dhCurves[s.CurveParam]()}
    s.dhParams.PrivateKey = make(dhkey, dhrsLen)
    _, err = io.ReadFull(f, s.dhParams.PrivateKey)
    if err != nil {
        return nil, err
    }
    s.dhParams.PublicKey = make(dhkey, dhrrLen)
    _, err = io.ReadFull(f, s.dhParams.PublicKey)
    if err != nil {
        return nil, err
    }
    s.dhPublicKey = make(dhkey, dhrpLen)
    _, err = io.ReadFull(f, s.dhPublicKey)
    if err != nil {
        return nil, err
    }
    
    _, err = io.ReadFull(f, buf[0:4])
    if err != nil {
        return nil, err
    }
    numEntries := binary.BigEndian.Uint32(buf[0:4])
    s.skippedKeys = list.New()
    for i := 0; i < int(numEntries); i++ {
        var sb [64]byte
        _, err = io.ReadFull(f, sb[:])
        if err != nil {
            return nil, err
        }
        s.skippedKeys.PushBack(storedkey{sb[0:32], sb[32:64]})
    }
    s.streamCipher = streamCiphers[s.StreamCipher]
    s.hkdf = hkdfs[s.HKDF]
    s.hmac = hmacs[s.HMAC]
    return s, nil
}

func saveBytes(f *os.File, b []byte) error {
    n := 0
    for n < 4 {
        i, err := f.Write(b[n:])
        if err != nil {
            return err
        }
        n += i
    }
    return nil
}

func saveUint32(f *os.File, v uint32) error {
    var b [4]byte
    binary.BigEndian.PutUint32(b[:], v)
    return saveBytes(f, b[:])
}

func saveUint8(f *os.File, v uint8) error {
    var b [1]byte
    b[0] = byte(v)
    return saveBytes(f, b[:])
}

func saveBool(f *os.File, v bool) error {
    var b [1]byte
    b[0] = 0
    if v {
        b[0] = 1
    }
    return saveBytes(f, b[:])
}

func saveKey(f *os.File, k key) error {
    var b [32]byte
    copy(b[:], k)
    return saveBytes(f, b[:])
}

func axolotlSaveTo(s *State, fileName string) error {
    f, err := os.Open(fileName)
    if err != nil {
        return err
    }
    defer f.Close()
    err = saveUint8(f, s.CurveParam)
    if err != nil {
        return err
    }
    err = saveUint8(f, s.StreamCipher)
    if err != nil {
        return err
    }
    err = saveUint8(f, s.HKDF)
    if err != nil {
        return err
    }
    err = saveUint8(f, s.HMAC)
    if err != nil {
        return err
    }
    err = saveBool(f, s.SenderSide)
    if err != nil {
        return err
    }
    err = saveBool(f, s.ratchetFlag)
    if err != nil {
        return err
    }
    err = saveUint32(f, s.msgNumS)
    if err != nil {
        return err
    }
    err = saveUint32(f, s.msgNumR)
    if err != nil {
        return err
    }
    err = saveUint32(f, s.prevMsgNumS)
    if err != nil {
        return err
    }
    err = saveKey(f, s.rootKey)
    if err != nil {
        return err
    }
    err = saveKey(f, s.hdrKeyS)
    if err != nil {
        return err
    }
    err = saveKey(f, s.hdrKeyR)
    if err != nil {
        return err
    }
    err = saveKey(f, s.nextHdrKeyS)
    if err != nil {
        return err
    }
    err = saveKey(f, s.nextHdrKeyR)
    if err != nil {
        return err
    }
    err = saveKey(f, s.chainKeyS)
    if err != nil {
        return err
    }
    err = saveKey(f, s.chainKeyR)
    if err != nil {
        return err
    }
    err = saveUint32(f, uint32(len(s.dhParams.PrivateKey)))
    if err != nil {
        return err
    }
    err = saveUint32(f, uint32(len(s.dhParams.PublicKey)))
    if err != nil {
        return err
    }
    err = saveUint32(f, uint32(len(s.dhPublicKey)))
    if err != nil {
        return err
    }
    err = saveBytes(f, s.dhParams.PrivateKey)
    if err != nil {
        return err
    }
    err = saveBytes(f, s.dhParams.PublicKey)
    if err != nil {
        return err
    }
    err = saveBytes(f, s.dhPublicKey)
    if err != nil {
        return err
    }
    err = saveUint32(f, uint32(s.skippedKeys.Len()))
    if err != nil {
        return err
    }
    for e := s.skippedKeys.Front(); e != nil; e = e.Next() {
        err = saveBytes(f, e.Value.(storedkey)[0])
        if err != nil {
            return err
        }
        err = saveBytes(f, e.Value.(storedkey)[1])
        if err != nil {
            return err
        }
    }
    return nil
}