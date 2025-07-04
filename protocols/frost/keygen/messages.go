package keygen

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/xlabs/multi-party-sig/internal/types"
	"github.com/xlabs/multi-party-sig/pkg/hash"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/math/polynomial"
	zksch "github.com/xlabs/multi-party-sig/pkg/zk/sch"
	common "github.com/xlabs/tss-common"
)

func makeBroadcast2Message(Phi_i *polynomial.Exponent, Sigma_i *zksch.Proof, Commitment []byte) (*Broadcast2, error) {
	phii, err := Phi_i.MarshalBinary()
	if err != nil {
		return nil, err
	}

	sigmai, err := cbor.Marshal(Sigma_i)
	if err != nil {
		return nil, err
	}

	return &Broadcast2{
		Phii:       phii,
		Sigmai:     sigmai,
		Commitment: Commitment,
	}, nil
}

// GetProtocol implements round.Content.
func (b *Broadcast2) GetProtocol() common.ProtocolType {
	return common.ProtocolFROST
}

// Reliable implements round.ReliableBroadcastContent.
func (b *Broadcast2) Reliable() bool {
	return true
}

// RoundNumber implements round.Content.
func (x *Broadcast2) RoundNumber() int {
	return 2
}

// ValidateBasic implements round.Content.
func (x *Broadcast2) ValidateBasic() bool {
	if x == nil {
		return false
	}

	return len(x.Phii) > 0 && len(x.Sigmai) > 0 && len(x.Commitment) > 0
}

func makeBroadcast3Message(c_l types.RID, decommitment hash.Decommitment) *Broadcast3 {
	return &Broadcast3{
		Cl:           c_l,
		Decommitment: decommitment,
		sizeCache:    0,
	}
}

func (b *Broadcast3) GetProtocol() common.ProtocolType {
	return common.ProtocolFROST
}

// Reliable implements round.BroadcastRoundContent.
func (b *Broadcast3) Reliable() bool {
	return true
}

// RoundNumber implements round.Content.
func (x *Broadcast3) RoundNumber() int {
	return 3
}

// ValidateBasic implements round.Content.
func (x *Broadcast3) ValidateBasic() bool {
	if x == nil {
		return false
	}

	return len(x.Decommitment) > 0 && len(x.Cl) > 0
}

func createMessage3(f_li curve.Scalar) (*Message3, error) {
	scalarbits, err := f_li.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &Message3{
		FLi: scalarbits,
	}, nil
}

func (b *Message3) GetProtocol() common.ProtocolType {
	return common.ProtocolFROST
}

// RoundNumber implements round.Content.
func (x *Message3) RoundNumber() int {
	return 3
}

// ValidateBasic implements round.Content.
func (x *Message3) ValidateBasic() bool {
	if x == nil {
		return false
	}

	return len(x.FLi) > 0
}
