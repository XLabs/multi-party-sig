package sign

import (
	"errors"

	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/round"
	zklogstar "github.com/xlabs/multi-party-sig/pkg/zk/logstar"
	common "github.com/xlabs/tss-common"
)

var _ round.Round = (*round4)(nil)

type round4 struct {
	*round3
	// DeltaShares[j] = δⱼ
	DeltaShares map[party.ID]curve.Scalar

	// BigDeltaShares[j] = Δⱼ = [kⱼ]•Γⱼ
	BigDeltaShares map[party.ID]curve.Point

	// Gamma = ∑ᵢ Γᵢ
	Gamma curve.Point

	// ChiShare = χᵢ
	ChiShare curve.Scalar

	verifiedMessage4 map[party.ID]struct{}
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - store δⱼ, Δⱼ
func (r *round4) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*Broadcast4)
	if !ok || !body.ValidateBasic() {
		return round.ErrInvalidContent
	}
	deltaShare, bigDeltaShare, err := body.UnmarshalContent(r.Group())
	if err != nil {
		return err
	}

	if deltaShare.IsZero() || bigDeltaShare.IsIdentity() {
		return round.ErrNilFields
	}

	r.BigDeltaShares[msg.From] = bigDeltaShare
	r.DeltaShares[msg.From] = deltaShare

	return nil
}

// VerifyMessage implements round.Round.
//
// - Verify Π(log*)(ϕ”ᵢⱼ, Δⱼ, Γ).
func (r *round4) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*Message4)
	if !ok || !body.ValidateBasic() {
		return round.ErrInvalidContent
	}

	proofLog, err := body.UnmarshalContent(r.Group())
	if err != nil {
		return round.ErrInvalidContent
	}

	zkLogPublic := zklogstar.Public{
		C:      r.K[from],
		X:      r.BigDeltaShares[from],
		G:      r.Gamma,
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}
	if !proofLog.Verify(r.HashForID(from), zkLogPublic) {
		return errors.New("failed to validate log proof")
	}

	r.verifiedMessage4[from] = struct{}{}
	return nil
}

// StoreMessage implements round.Round.
func (round4) StoreMessage(round.Message) error {
	return nil
}

func (r round4) CanFinalize() bool {
	t := r.Threshold() + 1
	if len(r.verifiedMessage4) < t ||
		len(r.DeltaShares) == 0 ||
		len(r.BigDeltaShares) == 0 {
		return false
	}

	for _, pid := range r.OtherPartyIDs() {
		if _, ok := r.verifiedMessage4[pid]; !ok {
			return false
		}

		if _, ok := r.DeltaShares[pid]; !ok {
			return false
		}

		if _, ok := r.BigDeltaShares[pid]; !ok {
			return false
		}
	}
	return true
}

// Finalize implements round.Round
//
// - set δ = ∑ⱼ δⱼ
// - set Δ = ∑ⱼ Δⱼ
// - verify Δ = [δ]G
// - compute σᵢ = rχᵢ + kᵢm.
func (r *round4) Finalize(out chan<- common.ParsedMessage) (round.Session, error) {
	// δ = ∑ⱼ δⱼ
	// Δ = ∑ⱼ Δⱼ
	Delta := r.Group().NewScalar()
	BigDelta := r.Group().NewPoint()
	for _, j := range r.PartyIDs() {
		Delta.Add(r.DeltaShares[j])
		BigDelta = BigDelta.Add(r.BigDeltaShares[j])
	}

	// Δ == [δ]G
	deltaComputed := Delta.ActOnBase()
	if !deltaComputed.Equal(BigDelta) {
		return r.AbortRound(errors.New("computed Δ is inconsistent with [δ]G")), nil
	}

	deltaInv := r.Group().NewScalar().Set(Delta).Invert() // δ⁻¹
	BigR := deltaInv.Act(r.Gamma)                         // R = [δ⁻¹] Γ
	R := BigR.XScalar()                                   // r = R|ₓ

	// km = Hash(m)⋅kᵢ
	km := curve.FromHash(r.Group(), r.Message)
	km.Mul(r.KShare)

	// σᵢ = rχᵢ + kᵢm
	SigmaShare := r.Group().NewScalar().Set(R).Mul(r.ChiShare).Add(km)

	// Send to all
	msg, err := makeBroadcast5(SigmaShare)
	if err != nil {
		return r, err
	}
	err = r.BroadcastMessage(out, msg)
	if err != nil {
		return r, err
	}
	return &round5{
		round4:      r,
		SigmaShares: map[party.ID]curve.Scalar{r.SelfID(): SigmaShare},
		Delta:       Delta,
		BigDelta:    BigDelta,
		BigR:        BigR,
		R:           R,
	}, nil
}

// MessageContent implements round.Round.
func (r *round4) MessageContent() round.Content {
	return &Message4{}
}

// BroadcastContent implements round.BroadcastRound.
func (r *round4) BroadcastContent() round.BroadcastContent {
	return &Broadcast4{}
}

// Number implements round.Round.
func (round4) Number() round.Number { return 4 }
