package marshal

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"math"
)

var (
	ErrSizeOverflow    = errors.New("part of the proof is too large to encode as uint16")
	ErrInvalidDataSize = errors.New("data is too short to contain unmarshal sizes")
	errNilItem         = errors.New("nil item found")
)

/*
Primitive represents a type that can be marshaled and unmarshaled in a ZK proof.

It is similar to encoding.BinaryMarshaler and encoding.BinaryUnmarshaler,
but also requires an AnnouncedLen method, which returns the expected
maximum byte size of the MarshalBinary output.

This is used to ensure that the sizes of each item can be encoded as uint16,
which is important for keeping the overall proof size small.
*/
type Primitive interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	// returns the expected max byte size of MarshalBinary output.
	// returns -1 for error.
	AnnouncedLen() int
}

// Since ZK proofs use relatively little memory, we store their numbers in uint16.

// WritePrimitives writes uint16 sizes for each item, then marshal
// each item and appends it to the buffer.
func WritePrimitives(buf *bytes.Buffer, toMarshal ...Primitive) error {
	items := make([][]byte, len(toMarshal))
	totalLength := 0

	for i, item := range toMarshal {
		if item == nil {
			return errNilItem
		}
		announcedLen := item.AnnouncedLen()
		if announcedLen > math.MaxUint16 {
			return ErrSizeOverflow
		}
		if announcedLen <= 0 {
			return errors.New("item has non-positive announced length")
		}

		b, err := item.MarshalBinary()
		if err != nil {
			return err
		}

		items[i] = b
		totalLength += len(b)
	}

	buf.Grow(totalLength + 2*len(items)) // 2 bytes per size

	for _, b := range items {
		var tmp [2]byte
		binary.BigEndian.PutUint16(tmp[:], uint16(len(b)))
		_, _ = buf.Write(tmp[:]) // ignoring err since doc states it is always nil.
	}

	for _, b := range items {
		_, _ = buf.Write(b) // ignoring err since doc states it is always nil.
	}
	return nil
}

// readUint16Sizes reads numItems big-endian uint16 sizes from data, returning
// the sizes and the remaining data. It fails fast if data is too short.
func readUint16Sizes(numItems int, data []byte) ([]int, []byte, error) {
	need := 2 * numItems
	if len(data) < need {
		return nil, data, ErrInvalidDataSize
	}

	// prevent overflow in sum(sizes)
	if numItems > math.MaxInt32/2 {
		return nil, data, ErrInvalidDataSize
	}

	sizes := make([]int, numItems)
	for i := 0; i < numItems; i++ {
		sizes[i] = int(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}

	// ensure sufficient data remains
	if len(data) < sum(sizes) {
		return nil, data, ErrInvalidDataSize
	}

	return sizes, data, nil
}

func ReadPrimitives(data []byte, toUnmarshal ...Primitive) ([]byte, error) {
	sizes, data, err := readUint16Sizes(len(toUnmarshal), data)
	if err != nil {
		return nil, err
	}

	for i, size := range sizes {
		if toUnmarshal[i] == nil {
			return nil, errNilItem
		}

		if err := toUnmarshal[i].UnmarshalBinary(data[:size]); err != nil {
			return nil, err
		}

		data = data[size:]
	}

	return data, nil
}

func sum(sizes []int) int {
	total := 0
	for _, size := range sizes {
		total += size
	}
	return total
}
