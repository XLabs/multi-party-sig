package keygen

import (
	"errors"
	"fmt"

	"github.com/xlabs/multi-party-sig/internal/marshal"
	"github.com/xlabs/multi-party-sig/internal/types"
	"github.com/xlabs/multi-party-sig/pkg/hash"
	"github.com/xlabs/multi-party-sig/pkg/math/arith"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/paillier"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/pedersen"
	"github.com/xlabs/multi-party-sig/pkg/round"
	zkfac "github.com/xlabs/multi-party-sig/pkg/zk/fac"
	zkmod "github.com/xlabs/multi-party-sig/pkg/zk/mod"
	zkprm "github.com/xlabs/multi-party-sig/pkg/zk/prm"
	zksch "github.com/xlabs/multi-party-sig/pkg/zk/sch"
	common "github.com/xlabs/tss-common"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2
	// SchnorrCommitments[j] = Aⱼ
	// Commitment for proof of knowledge in the last round
	SchnorrCommitments map[party.ID]*zksch.Commitment // Aⱼ
}

var (
	ErrVSSPolynomialHasIncorrectConstant = errors.New("vss polynomial has incorrect constant")
	ErrVSSPolynomialHasIncorrectDegree   = errors.New("vss polynomial has incorrect degree")
)

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - verify length of Schnorr commitments
// - verify degree of VSS polynomial Fⱼ "in-the-exponent"
//   - if keygen, verify Fⱼ(0) != ∞
//   - if refresh, verify Fⱼ(0) == ∞
//
// - validate Paillier
// - validate Pedersen
// - validate commitments.
// - store ridⱼ, Cⱼ, Nⱼ, Sⱼ, Tⱼ, Fⱼ(X), Aⱼ.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*Broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// check nil
	if !body.ValidateBasic() {
		return round.ErrNilFields
	}

	// check RID lengths
	RID := types.RID(body.RID)
	if err := RID.Validate(); err != nil {
		return fmt.Errorf("rid: %w", err)
	}

	chainKey := types.RID(body.C)
	if err := chainKey.Validate(); err != nil {
		return fmt.Errorf("chainkey: %w", err)
	}

	// check decommitment
	decommitment := hash.Decommitment(body.Decommitment)
	if err := decommitment.Validate(); err != nil {
		return fmt.Errorf("decommitment: %w", err)
	}

	VSSPolynomial, err := body.unmarshalVssExpoly(r.Group(), r.Threshold(), r.VSSSecret.Constant().IsZero())
	if err != nil {
		return fmt.Errorf("vss polynomial: %w", err)
	}

	// Set Paillier
	N, S, T, err := body.unmarshalPaillierAndPedersen()
	if err != nil {
		return fmt.Errorf("saferith: %w", err)
	}

	// Verify Pedersen
	if err := pedersen.ValidateParameters(N, S, T); err != nil {
		return err
	}

	schnorrCommitment := zksch.EmptyCommitment(r.Group())
	if err := marshal.Decode(body.SchnorrCommitments, schnorrCommitment); err != nil {
		return fmt.Errorf("schnorr commitment: %w", err)
	}

	elgamalPublic, err := r.Group().UnmarshalPoint(body.ElGamalPublic)
	if err != nil {
		return fmt.Errorf("elgamal public key: %w", err)
	}

	from := msg.From

	// Verify decommit
	if !r.HashForID(from).Decommit(r.Commitments[from], body.Decommitment,
		RID, chainKey, VSSPolynomial, schnorrCommitment, elgamalPublic, N, S, T) {
		return errors.New("failed to decommit")
	}

	r.RIDs[from] = RID
	r.ChainKeys[from] = chainKey
	r.PaillierPublic[from] = paillier.NewPublicKey(N)
	r.Pedersen[from] = pedersen.New(arith.ModulusFromN(N), S, T)
	r.VSSPolynomials[from] = VSSPolynomial
	r.SchnorrCommitments[from] = schnorrCommitment
	r.ElGamalPublic[from] = elgamalPublic

	return nil
}

// VerifyMessage implements round.Round.
func (round3) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round3) StoreMessage(round.Message) error { return nil }

func (r *round3) CanFinalize() bool {
	t := r.Threshold() + 1

	// quick check.
	if len(r.RIDs) < t ||
		len(r.ChainKeys) < t ||
		len(r.PaillierPublic) < t ||
		len(r.Pedersen) < t ||
		len(r.VSSPolynomials) < t ||
		len(r.SchnorrCommitments) < t ||
		len(r.ElGamalPublic) < t {
		return false
	}

	// check we received from all participants:
	for _, pid := range r.OtherPartyIDs() {
		if !r.receivedFromPartID(pid) {
			return false
		}
	}

	return true
}

func (r *round3) receivedFromPartID(l party.ID) bool {
	if _, ok := r.RIDs[l]; !ok {
		return false
	}

	if _, ok := r.ChainKeys[l]; !ok {
		return false
	}

	if _, ok := r.PaillierPublic[l]; !ok {
		return false
	}

	if _, ok := r.Pedersen[l]; !ok {
		return false
	}

	if _, ok := r.VSSPolynomials[l]; !ok {
		return false
	}

	if _, ok := r.SchnorrCommitments[l]; !ok {
		return false
	}

	if _, ok := r.ElGamalPublic[l]; !ok {
		return false
	}

	return true
}

// Finalize implements round.Round
//
// - set rid = ⊕ⱼ ridⱼ and update hash state
// - prove Nᵢ is Blum
// - prove Pedersen parameters
// - prove Schnorr for all coefficients of fᵢ(X)
//   - if refresh skip constant coefficient
//
// - send proofs and encryption of share for Pⱼ.
func (r *round3) Finalize(out chan<- common.ParsedMessage) (round.Session, error) {
	// c = ⊕ⱼ cⱼ
	chainKey := r.PreviousChainKey
	if chainKey == nil {
		chainKey = types.EmptyRID()
		for _, j := range r.PartyIDs() {
			chainKey.XOR(r.ChainKeys[j])
		}
	}
	// RID = ⊕ⱼ RIDⱼ
	rid := types.EmptyRID()
	for _, j := range r.PartyIDs() {
		rid.XOR(r.RIDs[j])
	}

	// temporary hash which does not modify the state
	h := r.Hash()
	_ = h.WriteAny(rid, r.SelfID())

	// Prove N is a blum prime with zkmod
	mod := zkmod.NewProof(h.Clone(), zkmod.Private{
		P:   r.PaillierSecret.P(),
		Q:   r.PaillierSecret.Q(),
		Phi: r.PaillierSecret.Phi(),
	}, zkmod.Public{N: r.PaillierPublic[r.SelfID()].N()}, r.Pool)

	// prove s, t are correct as aux parameters with zkprm
	prm := zkprm.NewProof(zkprm.Private{
		Lambda: r.PedersenSecret,
		Phi:    r.PaillierSecret.Phi(),
		P:      r.PaillierSecret.P(),
		Q:      r.PaillierSecret.Q(),
	}, h.Clone(), zkprm.Public{Aux: r.Pedersen[r.SelfID()]}, r.Pool)

	broadcastMsg, err := makeBroadcast4(mod, prm)
	if err != nil {
		return r, err
	}

	if err := r.BroadcastMessage(out, broadcastMsg); err != nil {
		return r, err
	}

	// create P2P messages with encrypted shares and zkfac proof
	for _, j := range r.OtherPartyIDs() {

		// Prove that the factors of N are relatively large
		fac := zkfac.NewProof(zkfac.Private{P: r.PaillierSecret.P(), Q: r.PaillierSecret.Q()}, h.Clone(), zkfac.Public{
			N:   r.PaillierPublic[r.SelfID()].N(),
			Aux: r.Pedersen[j],
		})

		// compute fᵢ(j)
		share := r.VSSSecret.Evaluate(j.Scalar(r.Group()))
		// Encrypt share
		shareCtx, _ := r.PaillierPublic[j].Enc(curve.MakeInt(share))

		msg, err := makeMessage4(shareCtx, fac)
		if err != nil {
			return r, err
		}

		if err := r.SendMessage(out, msg, j); err != nil {
			return r, err
		}
	}

	// Write rid to the hash state
	r.UpdateHashState(rid)
	return &round4{
		round3:    r,
		RID:       rid,
		ChainKey:  chainKey,
		validMod:  map[party.ID]bool{r.SelfID(): true},
		validPrms: map[party.ID]bool{r.SelfID(): true},
	}, nil
}

// MessageContent implements round.Round.
func (round3) MessageContent() round.Content { return nil }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &Broadcast3{
		RID:                []byte{},
		C:                  []byte{},
		VSSPolynomial:      []byte{},
		SchnorrCommitments: []byte{},
		ElGamalPublic:      []byte{},
		N:                  []byte{},
		S:                  []byte{},
		T:                  []byte{},
		Decommitment:       []byte{},
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
