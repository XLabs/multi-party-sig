package types

import (
	"fmt"

	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	common "github.com/xlabs/tss-common"
)

type Signature struct {
	R curve.Point
	S curve.Scalar
}

var (
	ErrNilSignatureData = fmt.Errorf("signature data is nil")
	ErrEmptySignatureS  = fmt.Errorf("signature.S data is empty")
	ErrEmptySignatureR  = fmt.Errorf("signature.R data is empty")
)

func CommonSignatureDataTranslate(sig *common.SignatureData, grp curve.Curve) (*Signature, error) {
	if sig == nil {
		return nil, ErrNilSignatureData
	}
	if sig.S == nil {
		return nil, ErrEmptySignatureS
	}
	if sig.R == nil {
		return nil, ErrEmptySignatureR
	}

	z, err := grp.UnmarshalScalar(sig.S)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal S: %w", err)
	}

	R, err := grp.UnmarshalPoint(sig.R)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal R: %w", err)
	}

	return &Signature{
		R: R,
		S: z,
	}, nil
}
