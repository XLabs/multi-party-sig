package sign

import (
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/round"
	common "github.com/xlabs/tss-common"
)

func makeBroadcast2Message(Di, Ei curve.Point) (round.BroadcastContent, error) {
	DiBinary, err := Di.MarshalBinary()
	if err != nil {
		return nil, err
	}

	EiBinary, err := Ei.MarshalBinary()
	if err != nil {
		return nil, err
	}

	content := &Broadcast2{
		Di: DiBinary,
		Ei: EiBinary,
	}

	return content, nil
}

func (b *Broadcast2) GetProtocol() common.ProtocolType {
	return common.ProtocolFROST
}

func (b *Broadcast2) RoundNumber() int {
	return 2
}

func (b *Broadcast2) ValidateBasic() bool {
	if b == nil {
		return false
	}

	if len(b.Di) == 0 || len(b.Di) > 33 {
		return false
	}

	if len(b.Ei) == 0 || len(b.Ei) > 33 {
		return false
	}

	return true
}

func (b *Broadcast2) Reliable() bool {
	return true
}

// Broadcast3:
func makeBroadcast3Message(z_i curve.Scalar) (*Broadcast3, error) {
	z_iBinary, err := z_i.MarshalBinary()
	if err != nil {
		return nil, err
	}

	content := &Broadcast3{
		Zi: z_iBinary,
	}

	return content, nil
}

func (b *Broadcast3) RoundNumber() int {
	return 3
}

func (b *Broadcast3) ValidateBasic() bool {
	if b == nil {
		return false
	}

	if len(b.Zi) == 0 {
		return false
	}

	return true
}

func (b *Broadcast3) GetProtocol() common.ProtocolType {
	return common.ProtocolFROST
}

// This message should be broadcast, but not reliably.
// TODO: Check why they set it to false in the original code.
// perhaps this is a mistake.
func (b *Broadcast3) Reliable() bool {
	return false
}
