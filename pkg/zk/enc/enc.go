package zkenc

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
	// K = Enc₀(k;ρ)
	K *paillier.Ciphertext

	Prover *paillier.PublicKey
	Aux    *pedersen.Parameters
}
type Private struct {
	// K = k ∈ 2ˡ = Dec₀(K)
	// plaintext of K
	K *saferith.Int

	// Rho = ρ
	// nonce of K
	Rho *saferith.Nat
}

type Commitment struct {
	// S = sᵏtᵘ
	S *saferith.Nat
	// A = Enc₀ (α, r)
	A *paillier.Ciphertext
	// C = sᵃtᵍ
	C *saferith.Nat
}

type Proof struct {
	*Commitment
	// Z₁ = α + e⋅k
	Z1 *saferith.Int
	// Z₂ = r ⋅ ρᵉ mod N₀
	Z2 *saferith.Nat
	// Z₃ = γ + e⋅μ
	Z3 *saferith.Int
}

func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.A) {
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

	alpha := sample.IntervalLEps(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)
	mu := sample.IntervalLN(rand.Reader)
	gamma := sample.IntervalLEpsN(rand.Reader)

	A := public.Prover.EncWithNonce(alpha, r)

	commitment := &Commitment{
		S: public.Aux.Commit(private.K, mu),
		A: A,
		C: public.Aux.Commit(alpha, gamma),
	}

	e, _ := challenge(hash, group, public, commitment)

	z1 := new(saferith.Int).SetInt(private.K)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)

	z2 := NModulus.ExpI(private.Rho, e)
	z2.ModMul(z2, r, N)

	z3 := new(saferith.Int).Mul(e, mu, -1)
	z3.Add(z3, gamma, -1)

	return &Proof{
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		Z3:         z3,
	}
}

func (p *Proof) Verify(group curve.Curve, hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	prover := public.Prover

	if !arith.IsInIntervalLEps(p.Z1) {
		return false
	}

	e, err := challenge(hash, group, public, p.Commitment)
	if err != nil {
		return false
	}

	if !public.Aux.Verify(p.Z1, p.Z3, e, p.C, p.S) {
		return false
	}

	{
		// lhs = Enc(z₁;z₂)
		lhs := prover.EncWithNonce(p.Z1, p.Z2)

		// rhs = (e ⊙ K) ⊕ A
		rhs := public.K.Clone().Mul(prover, e).Add(prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *saferith.Int, err error) {
	err = hash.WriteAny(public.Aux, public.Prover, public.K,
		commitment.S, commitment.A, commitment.C)
	e = sample.IntervalScalar(hash.Digest(), group)
	return
}

var (
	errInvalidCommitment = errors.New("invalid commitment")
	errInvalidProof      = errors.New("invalid proof")
)

func (c *Commitment) MarshalBinary() ([]byte, error) {
	if c == nil || c.S == nil || c.A == nil || c.C == nil {
		return nil, errInvalidCommitment
	}

	buf := bytes.NewBuffer(nil)

	if err := marshal.WritePrimitives(buf, c.S, c.A, c.C); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary unmarshals a Commitment from data and returns the remaining bytes.
func (c *Commitment) UnmarshalBinary(data []byte) ([]byte, error) {
	if c == nil {
		return nil, errInvalidCommitment
	}

	c.S = new(saferith.Nat)
	c.A = new(paillier.Ciphertext)
	c.C = new(saferith.Nat)

	return marshal.ReadPrimitives(data, c.S, c.A, c.C)
}

func (p *Proof) MarshalBinary() ([]byte, error) {
	if p == nil || p.Z1 == nil || p.Z2 == nil || p.Z3 == nil || p.Commitment == nil {
		return nil, errInvalidProof
	}

	commitmentBytes, err := p.Commitment.MarshalBinary()
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(commitmentBytes)

	if err := marshal.WritePrimitives(buf, p.Z1, p.Z2, p.Z3); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary unmarshals a Proof from data.
func (p *Proof) UnmarshalBinary(data []byte) error {
	if p == nil {
		return errInvalidProof
	}

	// Commitment first
	p.Commitment = &Commitment{}
	remaining, err := p.Commitment.UnmarshalBinary(data)
	if err != nil {
		return err
	}

	p.Z1 = new(saferith.Int)
	p.Z2 = new(saferith.Nat)
	p.Z3 = new(saferith.Int)

	_, err = marshal.ReadPrimitives(remaining, p.Z1, p.Z2, p.Z3)
	return err
}
