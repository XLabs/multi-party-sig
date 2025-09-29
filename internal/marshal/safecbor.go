package marshal

import (
	"bytes"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

var encMode cbor.EncMode
var decMode cbor.DecMode

// currently using default options but can be changed later if needed.
func init() {
	cborDecOptions := cbor.DecOptions{
		DupMapKey:                cbor.DupMapKeyQuiet,
		MaxNestedLevels:          4,
		MaxArrayElements:         1 << 10,
		MaxMapPairs:              1 << 10,
		IndefLength:              cbor.IndefLengthForbidden,
		TagsMd:                   cbor.TagsAllowed,
		IntDec:                   cbor.IntDecConvertNone, // not allowed to change type of int values
		MapKeyByteString:         cbor.MapKeyByteStringForbidden,
		ExtraReturnErrors:        cbor.ExtraDecErrorUnknownField,
		UTF8:                     cbor.UTF8RejectInvalid,
		FieldNameMatching:        cbor.FieldNameMatchingCaseSensitive,
		ByteStringToString:       cbor.ByteStringToStringForbidden,
		FieldNameByteString:      cbor.FieldNameByteStringForbidden,
		NaN:                      cbor.NaNDecodeForbidden,
		Inf:                      cbor.InfDecodeForbidden,
		ByteStringToTime:         cbor.ByteStringToTimeForbidden,
		ByteStringExpectedFormat: cbor.ByteStringExpectedFormatNone,
		BignumTag:                cbor.BignumTagAllowed,
		BinaryUnmarshaler:        cbor.BinaryUnmarshalerByteString, // invoke implementation of encoding.BinaryUnmarshaler for CBOR bytes.
		TextUnmarshaler:          cbor.TextUnmarshalerTextString,   // invoke implementation of encoding.UnmarshalText for CBOR texts.
		// defaults:
		TimeTag:                   0,
		DefaultMapType:            nil,
		BigIntDec:                 0,
		DefaultByteStringType:     nil,
		UnrecognizedTagToAny:      0,
		TimeTagToAny:              0,
		SimpleValues:              &cbor.SimpleValueRegistry{},
		JSONUnmarshalerTranscoder: nil,
	}

	cborEncOptions := cbor.EncOptions{
		Sort:          cbor.SortLengthFirst,
		ShortestFloat: cbor.ShortestFloatNone,
		NaNConvert:    cbor.NaNConvertNone,
		InfConvert:    cbor.InfConvertNone,
		BigIntConvert: cbor.BigIntConvertNone,
		Time:          cbor.TimeRFC3339,
		TimeTag:       cbor.EncTagRequired,
		IndefLength:   cbor.IndefLengthForbidden,
		TagsMd:        cbor.TagsAllowed,
		NilContainers: cbor.NilContainerAsNull,
		OmitEmpty:     cbor.OmitEmptyCBORValue,
		String:        cbor.StringToTextString,
		FieldName:     cbor.FieldNameToTextString,
		// ByteSliceLaterFormat:    0,
		ByteArray:               cbor.ByteArrayToByteSlice,
		BinaryMarshaler:         cbor.BinaryMarshalerByteString,
		TextMarshaler:           cbor.TextMarshalerTextString,
		JSONMarshalerTranscoder: nil,
	}

	enc, err := cborEncOptions.EncMode()
	if err != nil {
		panic(fmt.Errorf("cbor: cannot create encoder: %w", err))
	}

	dec, err := cborDecOptions.DecMode()
	if err != nil {
		panic(fmt.Errorf("cbor: cannot create decoder: %w", err))
	}

	encMode = enc
	decMode = dec
}

func NewEncoder(w io.Writer) *cbor.Encoder {
	return encMode.NewEncoder(w)
}

func NewDecoder(r io.Reader) *cbor.Decoder {
	// limit to 1 MB of data afterwards return io.EOF
	dec := decMode.NewDecoder(io.LimitReader(r, 1<<20))
	return dec
}

func Decode(bts []byte, val any) error {
	return NewDecoder(bytes.NewReader(bts)).Decode(val)
}

func Encode(val any) ([]byte, error) {
	buff := new(bytes.Buffer)
	err := NewEncoder(buff).Encode(val)
	if err != nil {
		return nil, err
	}

	return buff.Bytes(), nil
}
