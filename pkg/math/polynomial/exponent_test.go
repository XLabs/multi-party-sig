package polynomial

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/math/sample"
)

func TestExponent_Evaluate(t *testing.T) {
	group := curve.Secp256k1{}

	var lhs curve.Point
	for x := 0; x < 5; x++ {
		N := 1000
		secret := group.NewScalar()
		if x%2 == 0 {
			secret = sample.Scalar(rand.Reader, group)
		}
		poly := NewPolynomial(group, N, secret)
		polyExp := NewPolynomialExponent(poly)

		randomIndex := sample.Scalar(rand.Reader, group)

		lhs = poly.Evaluate(randomIndex).ActOnBase()
		rhs1 := polyExp.Evaluate(randomIndex)
		rhs2 := polyExp.evaluateClassic(randomIndex)

		require.Truef(t, lhs.Equal(rhs1), fmt.Sprint("base eval differs from horner", x))
		require.Truef(t, lhs.Equal(rhs2), fmt.Sprint("base eval differs from classic", x))
		require.Truef(t, rhs1.Equal(rhs2), fmt.Sprint("horner differs from classic", x))
	}
}

func TestSum(t *testing.T) {
	group := curve.Secp256k1{}

	N := 20
	Deg := 10

	randomIndex := sample.Scalar(rand.Reader, group)

	// compute f1(x) + f2(x) + …
	evaluationScalar := group.NewScalar()

	// compute F1(x) + F2(x) + …
	evaluationPartial := group.NewPoint()

	polys := make([]*Polynomial, N)
	polysExp := make([]*Exponent, N)
	for i := range polys {
		sec := sample.Scalar(rand.Reader, group)
		polys[i] = NewPolynomial(group, Deg, sec)
		polysExp[i] = NewPolynomialExponent(polys[i])

		evaluationScalar.Add(polys[i].Evaluate(randomIndex))
		evaluationPartial = evaluationPartial.Add(polysExp[i].Evaluate(randomIndex))
	}

	// compute (F1 + F2 + …)(x)
	summedExp, _ := Sum(polysExp)
	evaluationSum := summedExp.Evaluate(randomIndex)

	evaluationFromScalar := evaluationScalar.ActOnBase()
	assert.True(t, evaluationSum.Equal(evaluationFromScalar))
	assert.True(t, evaluationSum.Equal(evaluationPartial))
}

func TestMarshall(t *testing.T) {
	group := curve.Secp256k1{}

	szOfPolyCoeffs := 11
	sec := sample.Scalar(rand.Reader, group)
	// minus 1 because polynomial expects degree, not size.
	poly := NewPolynomial(group, szOfPolyCoeffs-1, sec)
	polyExp := NewPolynomialExponent(poly)

	exp2, err := UnmarshalBinary(polyExp.group, szOfPolyCoeffs, marshalExp(t, polyExp))
	require.NoError(t, err, "failed to Unmarshal")
	assert.True(t, polyExp.Equal(*exp2), "should be the same")

	data := marshalExp(t, polyExp)

	_, err = UnmarshalBinary(polyExp.group, szOfPolyCoeffs+1, data)
	require.Error(t, err, "should fail to unmarshal with short data")

	_, err = UnmarshalBinary(polyExp.group, 2, data)
	require.Error(t, err, "should fail to unmarshal with too little size")

	_, err = UnmarshalBinary(polyExp.group, szOfPolyCoeffs, nil)
	require.Error(t, err, "should fail to unmarshal with nil data")

	_, err = UnmarshalBinary(polyExp.group, szOfPolyCoeffs, []byte{})
	require.Error(t, err, "should fail to unmarshal with empty data")

	_, err = UnmarshalBinary(polyExp.group, -1, []byte{})
	require.Error(t, err, "should fail to unmarshal with negative degree")

	_, err = UnmarshalBinary(polyExp.group, 0, []byte{})
	require.Error(t, err, "should fail to unmarshal with zero degree")

	_, err = UnmarshalBinary(nil, 0, []byte{})
	require.Error(t, err, "should fail to unmarshal with zero degree")
}

func TestMarshallConst(t *testing.T) {
	group := curve.Secp256k1{}

	s := group.NewScalar()
	fmt.Println(s.IsZero())

	poly := NewPolynomial(group, 10, s) // const scalar.
	polyExp := NewPolynomialExponent(poly)

	polyExp.IsConstant = true
	data := marshalExp(t, polyExp)

	exp2, err := UnmarshalBinary(polyExp.group, len(polyExp.coefficients), data)
	require.NoError(t, err, "failed to Unmarshal")
	assert.True(t, polyExp.Equal(*exp2), "should be the same")

	// check that it is constant
	require.True(t, exp2.IsConstant, "should be constant")
}

func marshalExp(t *testing.T, polyExp *Exponent) []byte {
	data, err := polyExp.MarshalBinary()
	require.NoError(t, err, "failed to Marshal")
	require.NotEmpty(t, data, "should not be empty")
	return data
}
