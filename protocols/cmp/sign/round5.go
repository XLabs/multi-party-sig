package sign

import (
	"errors"

	"github.com/xlabs/multi-party-sig/pkg/ecdsa"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/round"
	common "github.com/xlabs/tss-common"
)

var _ round.Round = (*round5)(nil)

type round5 struct {
	*round4

	// SigmaShares[j] = σⱼ = m⋅kⱼ + χⱼ⋅R|ₓ
	SigmaShares map[party.ID]curve.Scalar

	// Delta = δ = ∑ⱼ δⱼ
	// computed from received shares
	Delta curve.Scalar

	// BigDelta = Δ = ∑ⱼ Δⱼ
	BigDelta curve.Point

	// R = [δ⁻¹] Γ
	BigR curve.Point

	// R = R|ₓ
	R curve.Scalar
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - save σⱼ
func (r *round5) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*Broadcast5)
	if !ok || !body.ValidateBasic() {
		return round.ErrInvalidContent
	}

	sigmaShare, err := body.UnmarshalContent(r.Group())
	if err != nil {
		return err
	}

	if sigmaShare.IsZero() {
		return round.ErrNilFields
	}

	r.SigmaShares[msg.From] = sigmaShare
	return nil
}

// VerifyMessage implements round.Round.
func (round5) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round5) StoreMessage(round.Message) error { return nil }

func (r round5) CanFinalize() bool {
	t := r.Threshold() + 1
	if len(r.SigmaShares) < t {
		return false
	}

	for _, pid := range r.OtherPartyIDs() {
		if _, ok := r.SigmaShares[pid]; !ok {
			return false
		}
	}
	return true
}

// Finalize implements round.Round
//
// - compute σ = ∑ⱼ σⱼ
// - verify signature.
func (r *round5) Finalize(chan<- common.ParsedMessage) (round.Session, error) {
	// compute σ = ∑ⱼ σⱼ
	Sigma := r.Group().NewScalar()
	for _, j := range r.PartyIDs() {
		Sigma.Add(r.SigmaShares[j])
	}

	signature := &ecdsa.Signature{
		R: r.BigR,
		S: Sigma,
	}

	if !signature.Verify(r.PublicKey, r.Message) {
		return r.AbortRound(errors.New("failed to validate signature")), nil
	}

	return r.ResultRound(signature), nil
}

// MessageContent implements round.Round.
func (r *round5) MessageContent() round.Content { return nil }

// BroadcastContent implements round.BroadcastRound.
func (r *round5) BroadcastContent() round.BroadcastContent {
	return &Broadcast5{}
}

// Number implements round.Round.
func (round5) Number() round.Number { return 5 }
