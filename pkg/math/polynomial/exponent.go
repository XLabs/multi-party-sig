package polynomial

import (
	"errors"
	"io"

	"github.com/cronokirby/saferith"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
)

type rawExponentData struct {
	IsConstant   bool
	Coefficients []curve.Point
}

// Exponent represent a polynomial F(X) whose coefficients belong to a group 𝔾.
type Exponent struct {
	group curve.Curve
	// IsConstant indicates that the constant coefficient is the identity.
	// We do this so that we never need to send an encoded Identity point, and thus consider it invalid
	IsConstant bool
	// coefficients is a list of curve.Point representing the coefficients of a polynomial over an elliptic curve.
	coefficients []curve.Point
}

// NewPolynomialExponent generates an Exponent polynomial F(X) = [secret + a₁•X + … + aₜ•Xᵗ]•G,
// with coefficients in 𝔾, and degree t.
func NewPolynomialExponent(polynomial *Polynomial) *Exponent {
	p := &Exponent{
		group:        polynomial.group,
		IsConstant:   polynomial.coefficients[0].IsZero(),
		coefficients: make([]curve.Point, 0, len(polynomial.coefficients)),
	}

	for i, c := range polynomial.coefficients {
		if p.IsConstant && i == 0 {
			continue
		}
		p.coefficients = append(p.coefficients, c.ActOnBase())
	}

	return p
}

// Evaluate returns F(x) = [secret + a₁•x + … + aₜ•xᵗ]•G.
func (p *Exponent) Evaluate(x curve.Scalar) curve.Point {
	result := p.group.NewPoint()

	for i := len(p.coefficients) - 1; i >= 0; i-- {
		// Bₙ₋₁ = [x]Bₙ  + Aₙ₋₁
		result = x.Act(result).Add(p.coefficients[i])
	}

	if p.IsConstant {
		// result is B₁
		// we want B₀ = [x]B₁ + A₀ = [x]B₁
		result = x.Act(result)
	}

	return result
}

// evaluateClassic evaluates a polynomial in a given variable index
// We do the classic method, where we compute all powers of x.
func (p *Exponent) evaluateClassic(x curve.Scalar) curve.Point {
	var tmp curve.Point

	xPower := p.group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
	result := p.group.NewPoint()

	if p.IsConstant {
		// since we start at index 1 of the polynomial, x must be x and not 1
		xPower.Mul(x)
	}

	for i := 0; i < len(p.coefficients); i++ {
		// tmp = [xⁱ]Aᵢ
		tmp = xPower.Act(p.coefficients[i])
		// result += [xⁱ]Aᵢ
		result = result.Add(tmp)
		// x = xⁱ⁺¹
		xPower.Mul(x)
	}
	return result
}

// Degree returns the degree t of the polynomial.
func (p *Exponent) Degree() int {
	if p.IsConstant {
		return len(p.coefficients)
	}
	return len(p.coefficients) - 1
}

func (p *Exponent) add(q *Exponent) error {
	if len(p.coefficients) != len(q.coefficients) {
		return errors.New("q is not the same length as p")
	}

	if p.IsConstant != q.IsConstant {
		return errors.New("p and q differ in 'IsConstant'")
	}

	for i := 0; i < len(p.coefficients); i++ {
		p.coefficients[i] = p.coefficients[i].Add(q.coefficients[i])
	}

	return nil
}

// Sum creates a new Polynomial in the Exponent, by summing a slice of existing ones.
func Sum(polynomials []*Exponent) (*Exponent, error) {
	var err error

	// Create the new polynomial by copying the first one given
	summed := polynomials[0].copy()

	// we assume all polynomials have the same degree as the first
	for j := 1; j < len(polynomials); j++ {
		err = summed.add(polynomials[j])
		if err != nil {
			return nil, err
		}
	}
	return summed, nil
}

func (p *Exponent) copy() *Exponent {
	q := &Exponent{
		group:        p.group,
		IsConstant:   p.IsConstant,
		coefficients: make([]curve.Point, 0, len(p.coefficients)),
	}
	for i := 0; i < len(p.coefficients); i++ {
		q.coefficients = append(q.coefficients, p.coefficients[i])
	}
	return q
}

// Equal returns true if p ≡ other.
func (p *Exponent) Equal(other Exponent) bool {
	if p.IsConstant != other.IsConstant {
		return false
	}
	if len(p.coefficients) != len(other.coefficients) {
		return false
	}
	for i := 0; i < len(p.coefficients); i++ {
		if !p.coefficients[i].Equal(other.coefficients[i]) {
			return false
		}
	}
	return true
}

// Constant returns the constant coefficient of the polynomial 'in the exponent'.
func (p *Exponent) Constant() curve.Point {
	c := p.group.NewPoint()
	if p.IsConstant {
		return c
	}
	return p.coefficients[0]
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (p *Exponent) WriteTo(w io.Writer) (int64, error) {
	data, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	total, err := w.Write(data)
	return int64(total), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (*Exponent) Domain() string {
	return "Exponent"
}

func EmptyExponent(group curve.Curve) *Exponent {
	// TODO create custom marshaller
	return &Exponent{group: group}
}

var (
	errNoGroup         = errors.New("can't unmarshal Exponent with no group")
	errIncorrectSize   = errors.New("data size is incorrect")
	errSizeNotPositive = errors.New("size must be positive")
	errNilExponent     = errors.New("can't marshal nil Exponent")
)

func (e *Exponent) MarshalBinary() ([]byte, error) {
	if e == nil {
		return nil, errNilExponent
	}
	if e.group == nil {
		return nil, errNoGroup
	}

	sizePerCoeff := e.group.PointBinarySize()
	data := make([]byte, 1+(len(e.coefficients)*sizePerCoeff))

	for i, v := range e.coefficients {
		bts, err := e.group.MarshalPoint(v)
		if err != nil {
			return nil, err
		}

		copy(data[i*sizePerCoeff:], bts)
	}

	constPos := len(e.coefficients) * sizePerCoeff
	data[constPos] = 0 // 0 // first byte is reserved for IsConstant
	if e.IsConstant {
		data[constPos] = 1
	}

	return data, nil
}

// receives the number of elements in the coefficients slice, ensuring
// the unmarshaller knows how many coefficients to expect.
func UnmarshalBinary(group curve.Curve, size int, data []byte) (*Exponent, error) {
	if group == nil {
		return nil, errNoGroup
	}

	if size <= 0 {
		return nil, errSizeNotPositive
	}

	pointSize := group.PointBinarySize()

	if len(data) != 1+size*pointSize {
		return nil, errIncorrectSize
	}

	p := &Exponent{
		group:        group,
		IsConstant:   false,
		coefficients: make([]curve.Point, 0, size),
	}

	for i := range size {
		point, err := group.UnmarshalPoint(data[i*pointSize : (i+1)*pointSize])
		if err != nil {
			return nil, err
		}

		p.coefficients = append(p.coefficients, point)
	}

	p.IsConstant = data[size*pointSize] != 0

	return p, nil

}
