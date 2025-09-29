package marshal

import (
	"math"
	"math/big"
)

// used so we can implement marshal/unmarshal interfaces on big.Int
type BigInt big.Int

func (p *BigInt) MarshalBinary() (data []byte, err error) {
	b := (*big.Int)(p)
	bts := b.Bytes()

	size := len(bts)
	if size > math.MaxUint16 {
		return nil, ErrSizeOverflow
	}

	data = make([]byte, 1+size)
	if b.Sign() >= 0 {
		data[0] = 1
	}

	copy(data[1:], bts)
	return data, nil
}

func (p *BigInt) AnnouncedLen() int {
	b := (*big.Int)(p)
	return b.BitLen() + 8 // value in bits, plus sign byte.
}

func (p *BigInt) UnmarshalBinary(data []byte) error {
	if p == nil {
		return errNilItem
	}

	if len(data) < 2 { // at least one byte for sign and one for value.
		return ErrInvalidDataSize
	}

	sgn := data[0]
	b := (*big.Int)(p)
	b.SetBytes(data[1:])
	if sgn == 0 {
		b.Neg(b)
	}

	return nil
}
