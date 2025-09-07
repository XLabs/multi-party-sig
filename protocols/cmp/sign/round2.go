package sign

import (
	"errors"
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/xlabs/multi-party-sig/internal/mta"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/paillier"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/round"
	zkenc "github.com/xlabs/multi-party-sig/pkg/zk/enc"
	zklogstar "github.com/xlabs/multi-party-sig/pkg/zk/logstar"
	common "github.com/xlabs/tss-common"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	// K[j] = Kⱼ = encⱼ(kⱼ)
	K map[party.ID]*paillier.Ciphertext
	// G[j] = Gⱼ = encⱼ(γⱼ)
	G map[party.ID]*paillier.Ciphertext
	// used to signal we can finalize safely the round
	verifiedMessage2 map[party.ID]struct{}

	// BigGammaShare[j] = Γⱼ = [γⱼ]•G
	BigGammaShare map[party.ID]curve.Point

	// GammaShare = γᵢ <- 𝔽
	GammaShare *saferith.Int
	// KShare = kᵢ  <- 𝔽
	KShare curve.Scalar

	// KNonce = ρᵢ <- ℤₙ
	// used to encrypt Kᵢ = Encᵢ(kᵢ)
	KNonce *saferith.Nat
	// GNonce = νᵢ <- ℤₙ
	// used to encrypt Gᵢ = Encᵢ(γᵢ)
	GNonce *saferith.Nat
}

// StoreBroadcastMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*Broadcast2)
	if !ok || !body.ValidateBasic() {
		return round.ErrInvalidContent
	}
	K, G, err := body.UnmarshalContent()
	if err != nil {
		return fmt.Errorf("round2: failed to unmarshal ciphertexts: %w", err)
	}

	if !r.Paillier[from].ValidateCiphertexts(K, G) {
		return errors.New("invalid K, G")
	}

	r.K[from] = K
	r.G[from] = G

	return nil
}

// VerifyMessage implements round.Round.
//
// - verify zkenc(Kⱼ).
// TODO: consider merging verifyMessage into storeMessage.
func (r *round2) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*Message2)
	if !ok || !body.ValidateBasic() {
		return round.ErrInvalidContent
	}

	proofEnc, err := body.UnmarshalContent()
	if err != nil {
		return fmt.Errorf("round2: failed to unmarshal proof: %w", err)
	}

	// TODO: this assumes we've received Broadcast2 before we reach this point.
	// (r.K[from] is nil and will FAIL to verify this proof). Consider how to handle this when Broadcast2 is not yet received.
	if !proofEnc.Verify(r.Group(), r.HashForID(from), zkenc.Public{
		K:      r.K[from],
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}) {
		return errors.New("failed to validate enc proof for K")
	}

	r.verifiedMessage2[from] = struct{}{}
	return nil
}

// StoreMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (round2) StoreMessage(round.Message) error { return nil }

func (r *round2) CanFinalize() bool {
	t := r.Threshold() + 1

	if len(r.verifiedMessage2) < t {
		return false
	}

	for _, pid := range r.OtherPartyIDs() {
		if _, ok := r.verifiedMessage2[pid]; !ok {
			return false
		}

		if _, ok := r.K[pid]; !ok {
			return false
		}

		if _, ok := r.G[pid]; !ok {
			return false
		}
	}
	return true
}

// Finalize implements round.Round
//
// - compute Hash(ssid, K₁, G₁, …, Kₙ, Gₙ).
func (r *round2) Finalize(out chan<- common.ParsedMessage) (round.Session, error) {
	msg, err := makeBroadcast3(r.BigGammaShare[r.SelfID()])
	if err != nil {
		return r, err
	}

	if err := r.BroadcastMessage(out, msg); err != nil {
		return r, err
	}

	otherIDs := r.OtherPartyIDs()
	type mtaOut struct {
		err       error
		DeltaBeta *saferith.Int
		ChiBeta   *saferith.Int
	}
	mtaOuts := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		DeltaBeta, DeltaD, DeltaF, DeltaProof := mta.ProveAffG(r.Group(), r.HashForID(r.SelfID()),
			r.GammaShare, r.BigGammaShare[r.SelfID()], r.K[j],
			r.SecretPaillier, r.Paillier[j], r.Pedersen[j])
		ChiBeta, ChiD, ChiF, ChiProof := mta.ProveAffG(r.Group(),
			r.HashForID(r.SelfID()), curve.MakeInt(r.SecretECDSA), r.ECDSA[r.SelfID()], r.K[j],
			r.SecretPaillier, r.Paillier[j], r.Pedersen[j])

		proof := zklogstar.NewProof(r.Group(), r.HashForID(r.SelfID()),
			zklogstar.Public{
				C:      r.G[r.SelfID()],
				X:      r.BigGammaShare[r.SelfID()],
				Prover: r.Paillier[r.SelfID()],
				Aux:    r.Pedersen[j],
			}, zklogstar.Private{
				X:   r.GammaShare,
				Rho: r.GNonce,
			})

		msg, err := makeMessage3(
			DeltaD,
			DeltaF,
			DeltaProof,
			ChiD,
			ChiF,
			ChiProof,
			proof,
		)
		if err != nil {
			return err
		}

		err = r.SendMessage(out, msg, j)
		return mtaOut{
			err:       err,
			DeltaBeta: DeltaBeta,
			ChiBeta:   ChiBeta,
		}
	})
	DeltaShareBetas := make(map[party.ID]*saferith.Int, len(otherIDs)-1)
	ChiShareBetas := make(map[party.ID]*saferith.Int, len(otherIDs)-1)
	for idx, mtaOutRaw := range mtaOuts {
		j := otherIDs[idx]
		m := mtaOutRaw.(mtaOut)
		if m.err != nil {
			return r, m.err
		}
		DeltaShareBetas[j] = m.DeltaBeta
		ChiShareBetas[j] = m.ChiBeta
	}

	return &round3{
		round2:           r,
		DeltaShareBeta:   DeltaShareBetas,
		ChiShareBeta:     ChiShareBetas,
		DeltaShareAlpha:  map[party.ID]*saferith.Int{},
		ChiShareAlpha:    map[party.ID]*saferith.Int{},
		verifiedMessage3: map[party.ID]struct{}{r.SelfID(): {}},
	}, nil
}

func (round2) MessageContent() round.Content { return &Message2{} }

// BroadcastContent implements round.BroadcastRound.
func (round2) BroadcastContent() round.BroadcastContent { return &Broadcast2{} }

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
