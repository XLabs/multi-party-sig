package keygen

import (
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
	"github.com/xlabs/multi-party-sig/internal/types"
	"github.com/xlabs/multi-party-sig/pkg/hash"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/math/polynomial"
	"github.com/xlabs/multi-party-sig/pkg/paillier"
	"github.com/xlabs/multi-party-sig/pkg/round"
	zkfac "github.com/xlabs/multi-party-sig/pkg/zk/fac"
	zkmod "github.com/xlabs/multi-party-sig/pkg/zk/mod"
	zkprm "github.com/xlabs/multi-party-sig/pkg/zk/prm"
	zksch "github.com/xlabs/multi-party-sig/pkg/zk/sch"
	common "github.com/xlabs/tss-common"
)

// GetProtocol implements round.Content.
func (b *Broadcast2) GetProtocol() common.ProtocolType {
	return common.ProtocolECDSA // TODO: Should we add some modifier? stating this is ecdsa:keygen?
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

	return len(x.Commitment) > 0
}

// / Broadcast3:
func makeBroadcast3(
	// RID = RIDᵢ
	RID types.RID,
	C types.RID, //chainkey RID
	// VSSPolynomial = Fᵢ(X) VSSPolynomial
	VSSPolynomial *polynomial.Exponent,
	// SchnorrCommitments = Aᵢ Schnorr commitment for the final confirmation
	SchnorrCommitments *zksch.Commitment,
	ElGamalPublic curve.Point,
	// N Paillier and Pedersen N = p•q, p ≡ q ≡ 3 mod 4
	N *saferith.Modulus,
	// S = r² mod N
	S *saferith.Nat,
	// T = Sˡ mod N
	T *saferith.Nat,
	// Decommitment = uᵢ decommitment bytes
	Decommitment hash.Decommitment,

) (round.Content, error) {
	vssPoly, err := VSSPolynomial.MarshalBinary()
	if err != nil {
		return nil, err
	}

	crv := ElGamalPublic.Curve()
	elPublicBytes, err := crv.MarshalPoint(ElGamalPublic)
	if err != nil {
		return nil, err
	}

	schnorrCommitment, err := SchnorrCommitments.MarshalBinary()
	if err != nil {
		return nil, err
	}

	Nbytes, err := N.MarshalBinary()
	if err != nil {
		return nil, err
	}

	SBytes, err := S.MarshalBinary()
	if err != nil {
		return nil, err
	}

	TBytes, err := T.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &Broadcast3{
		RID:                RID,
		C:                  C,
		VSSPolynomial:      vssPoly,
		SchnorrCommitments: schnorrCommitment,
		ElGamalPublic:      elPublicBytes,
		N:                  Nbytes,
		S:                  SBytes,
		T:                  TBytes,
		Decommitment:       Decommitment,
	}, nil
}

func (body *Broadcast3) unmarshalVssExpoly(crv curve.Curve, threshold int, vssConstant bool) (*polynomial.Exponent, error) {
	vssSize := threshold + 1
	if vssConstant {
		// polynomial[0] is not sent in refresh mode ( due to it being the identity point ) as optimization.
		vssSize -= 1
	}

	VSSPolynomial, err := polynomial.UnmarshalBinary(crv, vssSize, body.VSSPolynomial)
	if err != nil {
		return nil, err
	}

	// check that the constant coefficient is 0
	// if refresh then the polynomial is constant
	if vssConstant != VSSPolynomial.IsConstant {
		return nil, ErrVSSPolynomialHasIncorrectConstant
	}

	// check deg(Fⱼ) = t
	if VSSPolynomial.Degree() != threshold {
		return nil, ErrVSSPolynomialHasIncorrectDegree
	}

	return VSSPolynomial, nil
}

func (b *Broadcast3) unmarshalPaillierAndPedersen() (*saferith.Modulus, *saferith.Nat, *saferith.Nat, error) {
	N := &saferith.Modulus{}
	if err := N.UnmarshalBinary(b.N); err != nil {
		return nil, nil, nil, fmt.Errorf("saferith: %w", err)
	}

	if err := paillier.ValidateN(N); err != nil {
		return nil, nil, nil, fmt.Errorf("paillier: %w", err)
	}

	S := &saferith.Nat{}
	if err := S.UnmarshalBinary(b.S); err != nil {
		return nil, nil, nil, fmt.Errorf("saferith: %w", err)
	}

	T := &saferith.Nat{}
	if err := T.UnmarshalBinary(b.T); err != nil {
		return nil, nil, nil, fmt.Errorf("saferith: %w", err)
	}

	return N, S, T, nil
}

// GetProtocol implements round.Content.
func (b *Broadcast3) GetProtocol() common.ProtocolType {
	return common.ProtocolECDSA
}

// Reliable implements round.ReliableBroadcastContent.
func (b *Broadcast3) Reliable() bool {
	return true
}

// RoundNumber implements round.Content.
func (x *Broadcast3) RoundNumber() int {
	return 3
}

// ValidateBasic implements round.Content.
func (x *Broadcast3) ValidateBasic() bool {
	// check no len 0 fields:
	return (x != nil &&
		len(x.RID) > 0 &&
		len(x.C) > 0 &&
		len(x.VSSPolynomial) > 0 &&
		len(x.SchnorrCommitments) > 0 &&
		len(x.ElGamalPublic) > 0 &&
		len(x.N) > 0 &&
		len(x.S) > 0 &&
		len(x.T) > 0 &&
		len(x.Decommitment) > 0)
}

// Round 4:
func makeMessage4(
	// Share = Encᵢ(x) is the encryption of the receivers share
	share *paillier.Ciphertext,
	// Fac = zkfac.Proof
	fac *zkfac.Proof,
) (round.Content, error) {
	shareBytes, err := share.MarshalBinary()
	if err != nil {
		return nil, err
	}

	facBytes, err := fac.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &Message4{
		Share: shareBytes,
		Fac:   facBytes,
	}, nil
}

// GetProtocol implements round.Content.
func (b *Message4) GetProtocol() common.ProtocolType {
	return common.ProtocolECDSA
}

// Reliable implements round.ReliableBroadcastContent.
func (b *Message4) Reliable() bool {
	return false // This is a unicast message.
}

// RoundNumber implements round.Content.
func (x *Message4) RoundNumber() int {
	return 4
}

// ValidateBasic implements round.Content.
func (x *Message4) ValidateBasic() bool {
	return x != nil && len(x.Share) > 0 && len(x.Fac) > 0
}

func (x *Message4) UnmarshalContent() (*paillier.Ciphertext, *zkfac.Proof, error) {
	ctx := &paillier.Ciphertext{}
	if err := ctx.UnmarshalBinary(x.Share); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal Share ciphertext: %w", err)
	}

	fac := &zkfac.Proof{}
	if err := fac.UnmarshalBinary(x.Fac); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal Fac proof: %w", err)
	}

	return ctx, fac, nil
}

func makeBroadcast4(
	// Mod = zkmod.Proof
	mod *zkmod.Proof,
	// Prm = zkprm.Proof
	prm *zkprm.Proof,
) (round.Content, error) {
	modBytes, err := cbor.Marshal(mod)
	if err != nil {
		return nil, err
	}

	prmBytes, err := cbor.Marshal(prm)
	if err != nil {
		return nil, err
	}

	return &Broadcast4{
		Mod: modBytes,
		Prm: prmBytes,
	}, nil
}

// Reliable implements round.BroadcastContent.
func (x *Broadcast4) Reliable() bool {
	return true // indicates that this message should be reliably broadcasted.
}

// GetProtocol implements round.Content.
func (x *Broadcast4) GetProtocol() common.ProtocolType {
	return common.ProtocolECDSA
}

// RoundNumber implements round.Content.
func (x *Broadcast4) RoundNumber() int {
	return 4
}

// ValidateBasic implements round.Content.
func (x *Broadcast4) ValidateBasic() bool {
	return x != nil && len(x.Mod) > 0 && len(x.Prm) > 0
}

func (x *Broadcast4) UnmarshalContent() (*zkmod.Proof, *zkprm.Proof, error) {
	// TODO: Using cbor is unsafe. might cause panic due to demand of large buffer.
	mod := &zkmod.Proof{}
	if err := cbor.Unmarshal(x.Mod, mod); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal Mod proof: %w", err)
	}

	// TODO: Using cbor is unsafe. might cause panic due to demand of large buffer.
	prm := &zkprm.Proof{}
	if err := cbor.Unmarshal(x.Prm, prm); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal Prm proof: %w", err)
	}

	return mod, prm, nil
}

// Broadcast5 is the content type for round 5 broadcast messages.
// type Broadcast5 struct {
// 	round.NormalBroadcastContent
// 	// SchnorrResponse is the Schnorr proof of knowledge of the new secret share
// 	SchnorrResponse *sch.Response
// }

func makeBroadcast5(
	// SchnorrResponse is the Schnorr proof of knowledge of the new secret share
	schnorrResponse *zksch.Response,
) (round.Content, error) {

	rspBytes, err := schnorrResponse.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &Broadcast5{
		SchnorrResponse: rspBytes,
	}, nil
}

func (x *Broadcast5) Reliable() bool {
	return true // indicates that this message should be reliably broadcasted.
}

// GetProtocol implements round.Content.
func (x *Broadcast5) GetProtocol() common.ProtocolType {
	return common.ProtocolECDSA
}

// RoundNumber implements round.Content.
func (x *Broadcast5) RoundNumber() int {
	return 5
}

// ValidateBasic implements round.Content.
func (x *Broadcast5) ValidateBasic() bool {
	return x != nil && len(x.SchnorrResponse) > 0
}

func (x *Broadcast5) UnmarshalContent(crv curve.Curve) (*zksch.Response, error) {
	return zksch.UnmarshalResponse(x.SchnorrResponse, crv)
}
