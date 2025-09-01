package zklogstar

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/xlabs/multi-party-sig/pkg/hash"
	"github.com/xlabs/multi-party-sig/pkg/math/arith"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/math/sample"
	"github.com/xlabs/multi-party-sig/pkg/paillier"
	"github.com/xlabs/multi-party-sig/pkg/pedersen"
	"github.com/xlabs/multi-party-sig/pkg/zk/marshal"
)

type Public struct {
	// C = Enc₀(x;ρ)
	// Encryption of x under the prover's key
	C *paillier.Ciphertext

	// X = x⋅G
	X curve.Point

	// G is the base point of the curve.
	// If G = nil, the default base point is used.
	G curve.Point

	Prover *paillier.PublicKey
	Aux    *pedersen.Parameters
}

type Private struct {
	// X is the plaintext of C and the discrete log of X.
	X *saferith.Int

	// Rho = ρ is nonce used to encrypt C.
	Rho *saferith.Nat
}

type Commitment struct {
	// S = sˣ tᵘ (mod N)
	S *saferith.Nat
	// A = Enc₀(alpha; r)
	A *paillier.Ciphertext
	// Y = α⋅G
	Y curve.Point
	// D = sᵃ tᵍ (mod N)
	D *saferith.Nat
}

type Proof struct {
	group curve.Curve
	*Commitment
	// Z1 = α + e x
	Z1 *saferith.Int
	// Z2 = r ρᵉ mod N
	Z2 *saferith.Nat
	// Z3 = γ + e μ
	Z3 *saferith.Int
}

func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.A) {
		return false
	}
	if p.Y.IsIdentity() {
		return false
	}
	if !arith.IsValidNatModN(public.Prover.N(), p.Z2) {
		return false
	}
	return true
}

func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N()
	NModulus := public.Prover.Modulus()

	if public.G == nil {
		public.G = group.NewBasePoint()
	}

	alpha := sample.IntervalLEps(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)
	mu := sample.IntervalLN(rand.Reader)
	gamma := sample.IntervalLEpsN(rand.Reader)

	commitment := &Commitment{
		A: public.Prover.EncWithNonce(alpha, r),
		Y: group.NewScalar().SetNat(alpha.Mod(group.Order())).Act(public.G),
		S: public.Aux.Commit(private.X, mu),
		D: public.Aux.Commit(alpha, gamma),
	}

	e, _ := challenge(hash, group, public, commitment)

	// z1 = α + e x,
	z1 := new(saferith.Int).SetInt(private.X)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)
	// z2 = r ρᵉ mod N,
	z2 := NModulus.ExpI(private.Rho, e)
	z2.ModMul(z2, r, N)
	// z3 = γ + e μ,
	z3 := new(saferith.Int).Mul(e, mu, -1)
	z3.Add(z3, gamma, -1)

	return &Proof{
		group:      group,
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		Z3:         z3,
	}
}

func (p *Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	if public.G == nil {
		public.G = p.group.NewBasePoint()
	}

	if !arith.IsInIntervalLEps(p.Z1) {
		return false
	}

	prover := public.Prover

	e, err := challenge(hash, p.group, public, p.Commitment)
	if err != nil {
		return false
	}

	if !public.Aux.Verify(p.Z1, p.Z3, e, p.D, p.S) {
		return false
	}

	{
		// lhs = Enc(z₁;z₂)
		lhs := prover.EncWithNonce(p.Z1, p.Z2)

		// rhs = (e ⊙ C) ⊕ A
		rhs := public.C.Clone().Mul(prover, e).Add(prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = [z₁]G
		lhs := p.group.NewScalar().SetNat(p.Z1.Mod(p.group.Order())).Act(public.G)

		// rhs = Y + [e]X
		rhs := p.group.NewScalar().SetNat(e.Mod(p.group.Order())).Act(public.X)
		rhs = rhs.Add(p.Y)

		if !lhs.Equal(rhs) {
			return false
		}

	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *saferith.Int, err error) {
	err = hash.WriteAny(public.Aux, public.Prover, public.C, public.X, public.G,
		commitment.S, commitment.A, commitment.Y, commitment.D)
	e = sample.IntervalScalar(hash.Digest(), group)
	return
}

func Empty(group curve.Curve) *Proof {
	return &Proof{
		group:      group,
		Commitment: &Commitment{Y: group.NewPoint()},
	}
}

var (
	errNilCommitment     = errors.New("nil logstar Commitment")
	errInvalidCommitment = errors.New("invalid logstar Commitment")
	errNilGroup          = errors.New("received nil Curve")
	errNilProof          = errors.New("nil logstar Proof")
	errInsufficientData  = errors.New("insufficient data to unmarshal logstar proof")
)

func (c *Commitment) MarshalBinary() ([]byte, error) {
	if c == nil || c.A == nil || c.Y == nil || c.S == nil || c.D == nil {
		return nil, errInvalidCommitment
	}
	var buf bytes.Buffer
	if err := marshal.WriteItemsToBuffer(&buf, c.S, c.A, c.D); err != nil {
		return nil, err
	}

	pt, err := c.Y.Curve().MarshalPoint(c.Y)
	if err != nil {
		return nil, err
	}
	buf.Write(pt)

	return buf.Bytes(), nil
}

func (c *Commitment) UnmarshalBinary(data []byte, grp curve.Curve) ([]byte, error) {
	if c == nil {
		return nil, errNilCommitment
	}

	if grp == nil {
		return nil, errNilGroup
	}

	sz, data, err := marshal.ReadUint16Sizes(3, data)
	if err != nil {
		return nil, err
	}

	c.S = new(saferith.Nat)
	if err = c.S.UnmarshalBinary(data[:sz[0]]); err != nil {
		return nil, err
	}
	data = data[sz[0]:]

	c.A = new(paillier.Ciphertext)
	if err := c.A.UnmarshalBinary(data[:sz[1]]); err != nil {
		return nil, err
	}
	data = data[sz[1]:]

	c.D = new(saferith.Nat)
	if err := c.D.UnmarshalBinary(data[:sz[2]]); err != nil {
		return nil, err
	}
	data = data[sz[2]:]

	ptByteSize := grp.PointBinarySize()
	if len(data) < ptByteSize {
		return nil, errInsufficientData
	}

	if c.Y, err = grp.UnmarshalPoint(data[:ptByteSize]); err != nil {
		return nil, err
	}

	return data[ptByteSize:], nil
}

func (p *Proof) MarshalBinary() ([]byte, error) {
	if p == nil || p.Commitment == nil || p.Z3 == nil || p.Z2 == nil || p.Z1 == nil {
		return nil, errNilProof
	}

	commbytes, err := p.Commitment.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(commbytes)

	if err := marshal.WriteItemsToBuffer(buf, p.Z1, p.Z2, p.Z3); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (p *Proof) UnmarshalBinary(data []byte) error {
	if p == nil {
		return errNilProof
	}
	if p.group == nil {
		return errNilGroup
	}

	p.Commitment = new(Commitment)
	data, err := p.Commitment.UnmarshalBinary(data, p.group)
	if err != nil {
		return err
	}

	sz, data, err := marshal.ReadUint16Sizes(3, data)
	if err != nil {
		return err
	}
	p.Z1 = new(saferith.Int)
	if err := p.Z1.UnmarshalBinary(data[:sz[0]]); err != nil {
		return err
	}
	data = data[sz[0]:]

	p.Z2 = new(saferith.Nat)
	if err := p.Z2.UnmarshalBinary(data[:sz[1]]); err != nil {
		return err
	}
	data = data[sz[1]:]

	p.Z3 = new(saferith.Int)
	if err := p.Z3.UnmarshalBinary(data[:sz[2]]); err != nil {
		return err
	}

	return nil
}
