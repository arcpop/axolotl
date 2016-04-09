package axolotl

import (
	"encoding/binary"
	"io"
)


type message struct {
    headerNonceSize byte
    messageNonceSize byte
    headerLength uint32
    messageLength uint32
    headerNonce []byte
    messageNonce []byte
    headerData []byte
    messageData []byte
}


func serialize(m *message) []byte  {
    m.headerNonceSize = byte(len(m.headerNonce))
    m.messageNonceSize = byte(len(m.messageNonce))
    m.headerLength = uint32(len(m.headerData))
    m.messageLength = uint32(len(m.messageData))
    b := make([]byte, m.headerLength + m.messageLength + uint32(m.headerNonceSize) + uint32(m.messageNonceSize) + 10)
    b[0] = m.headerNonceSize
    b[1] = m.messageNonceSize
    binary.BigEndian.PutUint32(b[2:6], m.headerLength)
    binary.BigEndian.PutUint32(b[6:10], m.messageLength)
    
    tmp := uint32(10)
    copy(b[tmp : tmp + uint32(m.headerNonceSize)], m.headerNonce)
    
    tmp += uint32(m.headerNonceSize)
    copy(b[tmp : tmp + uint32(m.messageNonceSize)], m.messageNonce)
    
    tmp += uint32(m.messageNonceSize)
    copy(b[tmp : tmp + m.headerLength], m.headerData)
    
    tmp += m.headerLength
    copy(b[tmp : tmp + m.messageLength], m.messageData)
    
    return b
}

func deserialize(b []byte) (*message, error)  {
    if len(b) < 10 {
        return nil, ErrMalformedMessage
    }
    
    m := &message{}
    m.headerNonceSize = b[0]
    m.messageNonceSize = b[1]
    m.headerLength = binary.BigEndian.Uint32(b[2:6])
    m.messageLength = binary.BigEndian.Uint32(b[6:10])
    
    totalLength := 10 + uint32(m.headerNonceSize) + uint32(m.messageNonceSize) + m.headerLength + m.messageLength
    
    if uint32(len(b)) < totalLength {
        return nil, ErrMalformedMessage
    }
    
    tmp := uint32(10)
    m.headerNonce = make([]byte, m.headerNonceSize)
    copy(m.headerNonce, b[tmp : tmp + uint32(m.headerNonceSize)])
    
    tmp += uint32(m.headerNonceSize)
    m.messageNonce = make([]byte, m.messageNonceSize)
    copy(m.messageNonce, b[tmp : tmp + uint32(m.messageNonceSize)])
    
    tmp += uint32(m.messageNonceSize)
    m.headerData = make([]byte, m.headerLength)
    copy(m.headerData, b[tmp : tmp + m.headerLength])
    
    tmp += m.headerLength
    m.messageData = make([]byte, m.messageLength)
    copy(m.messageData, b[tmp : tmp + m.messageLength])
    
    return m, nil
}

func deserializeFromReader(rd io.Reader) (*message, error)  {
    var b[10]byte
    
    _, err := io.ReadFull(rd, b[:])
    if err != nil {
        return nil, err
    }
    
    m := &message{}
    m.headerNonceSize = b[0]
    m.messageNonceSize = b[1]
    m.headerLength = binary.BigEndian.Uint32(b[2:6])
    m.messageLength = binary.BigEndian.Uint32(b[6:10])
    
    m.headerNonce = make([]byte, m.headerNonceSize)
    _, err = io.ReadFull(rd, m.headerNonce)
    if err != nil {
        return nil, err
    }
    
    m.messageNonce = make([]byte, m.messageNonceSize)
    _, err = io.ReadFull(rd, m.messageNonce)
    if err != nil {
        return nil, err
    }
    
    m.headerData = make([]byte, m.headerLength)
    _, err = io.ReadFull(rd, m.headerData)
    if err != nil {
        return nil, err
    }
    
    m.messageData = make([]byte, m.messageLength)
    _, err = io.ReadFull(rd, m.messageData)
    if err != nil {
        return nil, err
    }
    return m, nil
}
