package keygen

import (
	"github.com/cronokirby/saferith"
	"github.com/xlabs/multi-party-sig/internal/types"
	"github.com/xlabs/multi-party-sig/pkg/hash"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/math/polynomial"
	"github.com/xlabs/multi-party-sig/pkg/paillier"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/pedersen"
	"github.com/xlabs/multi-party-sig/pkg/round"
	zksch "github.com/xlabs/multi-party-sig/pkg/zk/sch"
	common "github.com/xlabs/tss-common"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	// VSSPolynomials[j] = Fⱼ(X) = fⱼ(X)•G
	VSSPolynomials map[party.ID]*polynomial.Exponent

	// Commitments[j] = H(Keygen3ⱼ ∥ Decommitments[j])
	Commitments map[party.ID]hash.Commitment

	// RIDs[j] = ridⱼ
	RIDs map[party.ID]types.RID
	// ChainKeys[j] = cⱼ
	ChainKeys map[party.ID]types.RID

	// ShareReceived[j] = xʲᵢ
	// share received from party j
	ShareReceived map[party.ID]curve.Scalar

	ElGamalPublic map[party.ID]curve.Point
	// PaillierPublic[j] = Nⱼ
	PaillierPublic map[party.ID]*paillier.PublicKey

	// Pedersen[j] = (Nⱼ,Sⱼ,Tⱼ)
	Pedersen map[party.ID]*pedersen.Parameters

	ElGamalSecret curve.Scalar

	// PaillierSecret = (pᵢ, qᵢ)
	PaillierSecret *paillier.SecretKey

	// PedersenSecret = λᵢ
	// Used to generate the Pedersen parameters
	PedersenSecret *saferith.Nat

	// SchnorrRand = aᵢ
	// Randomness used to compute Schnorr commitment of proof of knowledge of secret share
	SchnorrRand *zksch.Randomness

	// Decommitment for Keygen3ᵢ
	Decommitment hash.Decommitment // uᵢ
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// Commitment = Vᵢ = H(ρᵢ, Fᵢ(X), Aᵢ, Yᵢ, Nᵢ, sᵢ, tᵢ, uᵢ)
	Commitment hash.Commitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
// - save commitment Vⱼ.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	if msg.From == r.SelfID() {
		return nil // avoid receiving own message
	}

	body, ok := msg.Content.(*Broadcast2)
	if !ok || body == nil || !body.ValidateBasic() {
		return round.ErrInvalidContent
	}

	commitment := hash.Commitment(body.Commitment)

	if err := commitment.Validate(); err != nil {
		return err
	}

	r.Commitments[msg.From] = commitment

	return nil
}

func (r round2) CanFinalize() bool {
	t := r.Threshold() + 1

	// quick check.
	if len(r.Commitments) < t {
		return false
	}

	// check we received from all participants:
	for _, l := range r.OtherPartyIDs() {
		if _, ok := r.Commitments[l]; !ok {
			return false
		}
	}

	return true
}

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - send all committed data.
func (r *round2) Finalize(out chan<- common.ParsedMessage) (round.Session, error) {
	// Send the message we created in Round1 to all
	msg, err := makeBroadcast3(
		r.RIDs[r.SelfID()],
		r.ChainKeys[r.SelfID()],
		r.VSSPolynomials[r.SelfID()],
		r.SchnorrRand.Commitment(),
		r.ElGamalPublic[r.SelfID()],
		r.Pedersen[r.SelfID()].N(),
		r.Pedersen[r.SelfID()].S(),
		r.Pedersen[r.SelfID()].T(),
		r.Decommitment,
	)

	if err != nil {
		return r, err
	}

	err = r.BroadcastMessage(out, msg)
	if err != nil {
		return r, err
	}
	return &round3{
		round2:             r,
		SchnorrCommitments: map[party.ID]*zksch.Commitment{r.SelfID(): r.SchnorrRand.Commitment()},
	}, nil
}

// PreviousRound implements round.Round.
func (r *round2) PreviousRound() round.Round { return r.round1 }

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (round2) BroadcastContent() round.BroadcastContent {
	return &Broadcast2{Commitment: []byte{}}
}

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
