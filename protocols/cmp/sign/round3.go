package sign

import (
	"errors"
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/round"
	zkaffg "github.com/xlabs/multi-party-sig/pkg/zk/affg"
	zklogstar "github.com/xlabs/multi-party-sig/pkg/zk/logstar"
	common "github.com/xlabs/tss-common"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2

	// DeltaShareAlpha[j] = αᵢⱼ
	DeltaShareAlpha map[party.ID]*saferith.Int
	// DeltaShareBeta[j] = βᵢⱼ
	DeltaShareBeta map[party.ID]*saferith.Int
	// ChiShareAlpha[j] = α̂ᵢⱼ
	ChiShareAlpha map[party.ID]*saferith.Int
	// ChiShareBeta[j] = β̂ᵢⱼ
	ChiShareBeta map[party.ID]*saferith.Int

	verifiedMessage3 map[party.ID]struct{}
}

type broadcast3 struct {
	round.NormalBroadcastContent
	BigGammaShare curve.Point // BigGammaShare = Γⱼ
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - store Γⱼ
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*Broadcast3)
	if !ok || !body.ValidateBasic() {
		return round.ErrInvalidContent
	}
	bigGammaShare, err := body.UnmarshalContent(r.Group())
	if err != nil {
		return fmt.Errorf("failed to unmarshal BigGammaShare: %w", err)
	}

	if bigGammaShare.IsIdentity() {
		return round.ErrNilFields
	}

	r.BigGammaShare[msg.From] = bigGammaShare

	return nil
}

// VerifyMessage implements round.Round.
//
// - verify zkproofs affg (2x) zklog*.
func (r *round3) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*Message3)
	if !ok || !body.ValidateBasic() {
		return round.ErrInvalidContent
	}

	// TODO: Assumes Broadcast3 has been received
	um3, err := body.UnmarshalContent(r.Group())
	if err != nil {
		return fmt.Errorf("failed to unmarshal Message3 content: %w", err)
	}

	if !um3.DeltaProof.Verify(r.HashForID(from), zkaffg.Public{
		Kv:       r.K[to],
		Dv:       um3.DeltaD,
		Fp:       um3.DeltaF,
		Xp:       r.BigGammaShare[from],
		Prover:   r.Paillier[from],
		Verifier: r.Paillier[to],
		Aux:      r.Pedersen[to],
	}) {
		return errors.New("failed to validate affg proof for Delta MtA")
	}

	if !um3.ChiProof.Verify(r.HashForID(from), zkaffg.Public{
		Kv:       r.K[to],
		Dv:       um3.ChiD,
		Fp:       um3.ChiF,
		Xp:       r.ECDSA[from],
		Prover:   r.Paillier[from],
		Verifier: r.Paillier[to],
		Aux:      r.Pedersen[to],
	}) {
		return errors.New("failed to validate affg proof for Chi MtA")
	}

	if !um3.ProofLog.Verify(r.HashForID(from), zklogstar.Public{
		C:      r.G[from],
		X:      r.BigGammaShare[from],
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}) {
		return errors.New("failed to validate log proof")
	}

	return nil
}

// StoreMessage implements round.Round.
//
// - Decrypt MtA shares,
// - save αᵢⱼ, α̂ᵢⱼ.
func (r *round3) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*Message3)
	um3, err := body.UnmarshalContent(r.Group())
	if err != nil {
		return fmt.Errorf("failed to unmarshal Message3 content: %w", err)
	}
	// αᵢⱼ
	DeltaShareAlpha, err := r.SecretPaillier.Dec(um3.DeltaD)
	if err != nil {
		return fmt.Errorf("failed to decrypt alpha share for delta: %w", err)
	}
	// α̂ᵢⱼ
	ChiShareAlpha, err := r.SecretPaillier.Dec(um3.ChiD)
	if err != nil {
		return fmt.Errorf("failed to decrypt alpha share for chi: %w", err)
	}

	r.DeltaShareAlpha[from] = DeltaShareAlpha
	r.ChiShareAlpha[from] = ChiShareAlpha

	return nil
}

func (r *round3) CanFinalize() bool {
	t := r.Threshold() + 1
	if len(r.BigGammaShare) < t || len(r.DeltaShareAlpha) < t || len(r.ChiShareAlpha) < t || len(r.verifiedMessage3) < t {
		return false
	}

	for _, pid := range r.OtherPartyIDs() {
		if _, ok := r.verifiedMessage3[pid]; !ok {
			return false
		}
		if _, ok := r.DeltaShareAlpha[pid]; !ok {
			return false
		}
		if _, ok := r.ChiShareAlpha[pid]; !ok {
			return false
		}
	}
	return true
}

// Finalize implements round.Round
//
// - Γ = ∑ⱼ Γⱼ
// - Δᵢ = [kᵢ]Γ
// - δᵢ = γᵢ kᵢ + ∑ⱼ δᵢⱼ
// - χᵢ = xᵢ kᵢ + ∑ⱼ χᵢⱼ.
func (r *round3) Finalize(out chan<- common.ParsedMessage) (round.Session, error) {
	// Γ = ∑ⱼ Γⱼ
	Gamma := r.Group().NewPoint()
	for _, BigGammaShare := range r.BigGammaShare {
		Gamma = Gamma.Add(BigGammaShare)
	}

	// Δᵢ = [kᵢ]Γ
	KShareInt := curve.MakeInt(r.KShare)
	BigDeltaShare := r.KShare.Act(Gamma)

	// δᵢ = γᵢ kᵢ
	DeltaShare := new(saferith.Int).Mul(r.GammaShare, KShareInt, -1)

	// χᵢ = xᵢ kᵢ
	ChiShare := new(saferith.Int).Mul(curve.MakeInt(r.SecretECDSA), KShareInt, -1)

	for _, j := range r.OtherPartyIDs() {
		//δᵢ += αᵢⱼ + βᵢⱼ
		DeltaShare.Add(DeltaShare, r.DeltaShareAlpha[j], -1)
		DeltaShare.Add(DeltaShare, r.DeltaShareBeta[j], -1)

		// χᵢ += α̂ᵢⱼ +  ̂βᵢⱼ
		ChiShare.Add(ChiShare, r.ChiShareAlpha[j], -1)
		ChiShare.Add(ChiShare, r.ChiShareBeta[j], -1)
	}

	zkPrivate := zklogstar.Private{
		X:   KShareInt,
		Rho: r.KNonce,
	}

	DeltaShareScalar := r.Group().NewScalar().SetNat(DeltaShare.Mod(r.Group().Order()))
	msg, err := makeBroadcast4(DeltaShareScalar, BigDeltaShare)
	if err != nil {
		return r, err
	}

	if err := r.BroadcastMessage(out, msg); err != nil {
		return r, err
	}

	otherIDs := r.OtherPartyIDs()
	errs := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		proofLog := zklogstar.NewProof(r.Group(), r.HashForID(r.SelfID()), zklogstar.Public{
			C:      r.K[r.SelfID()],
			X:      BigDeltaShare,
			G:      Gamma,
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkPrivate)

		msg, err := makeMessage4(proofLog)
		if err != nil {
			return err
		}

		if err := r.SendMessage(out, msg, j); err != nil {
			return err
		}
		return nil
	})
	for _, err := range errs {
		if err != nil {
			return r, err.(error)
		}
	}

	return &round4{
		round3:         r,
		DeltaShares:    map[party.ID]curve.Scalar{r.SelfID(): DeltaShareScalar},
		BigDeltaShares: map[party.ID]curve.Point{r.SelfID(): BigDeltaShare},
		Gamma:          Gamma,
		ChiShare:       r.Group().NewScalar().SetNat(ChiShare.Mod(r.Group().Order())),
	}, nil
}

// MessageContent implements round.Round.
func (r *round3) MessageContent() round.Content {
	return &Message3{}
}

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &Broadcast3{}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
