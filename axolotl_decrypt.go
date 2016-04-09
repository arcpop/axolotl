package axolotl

import (
    "io"
)

func axolotlDecryptMessage(s *State, rd io.Reader) ([]byte, error) {
    m, err := deserializeFromReader(rd)
    
    if err != nil {
        return nil, err
    }
    
    
    
}