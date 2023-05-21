package main

import (
	"encoding/binary"
	"fmt"
)

type Principal struct {
	Realm string

	Items [][]byte
}

func UnmarshalPrincipal(in []byte) (*Principal, int, error) {
	if len(in) < 12 {
		return nil, -1, fmt.Errorf("principal must be 12 length minimum")
	}

	princ := &Principal{Items: [][]byte{}}

	nextPos := 4

	//version := binary.BigEndian.Uint32(in[:nextPos])
	itemsCount := binary.BigEndian.Uint32(in[nextPos : nextPos+4])

	nextPos += 4
	realmLength := binary.BigEndian.Uint32(in[nextPos : nextPos+4])
	if len(in) < 12+int(realmLength) {
		return nil, -2, fmt.Errorf("unable to capture realm, length mismatch")
	}

	nextPos += 4
	princ.Realm = string(in[nextPos : nextPos+int(realmLength)])
	nextPos += int(realmLength)

	for i := 0; i < int(itemsCount); i++ {
		if len(in) < nextPos+4 {
			return nil, -3, fmt.Errorf("unable to capture item length, length mismatch")
		}

		itemLength := binary.BigEndian.Uint32(in[nextPos : nextPos+4])
		if len(in) < nextPos+int(itemLength) {
			return nil, -4, fmt.Errorf("unable to capture item data, length mismatch")
		}
		nextPos += 4

		princ.Items = append(princ.Items, in[nextPos:nextPos+int(itemLength)])
		nextPos += int(itemLength)
	}

	return princ, nextPos, nil
}
