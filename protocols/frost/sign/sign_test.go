package sign

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xlabs/multi-party-sig/internal/params"
	"github.com/xlabs/multi-party-sig/internal/test"
	"github.com/xlabs/multi-party-sig/pkg/eth"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/math/polynomial"
	"github.com/xlabs/multi-party-sig/pkg/math/sample"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/round"
	"github.com/xlabs/multi-party-sig/pkg/taproot"
	"github.com/xlabs/multi-party-sig/protocols/frost/keygen"
)

func SignEcSchnorr(secret curve.Scalar, m []byte) Signature {
	group := secret.Curve()

	// k is the first nonce
	k := sample.Scalar(rand.Reader, group)

	R := k.ActOnBase() // R == kG.

	// Hash the message and the public key
	challenge, err := intoEVMCompatibleChallenge(R, secret.ActOnBase(), messageHash(m))
	if err != nil {
		panic(err)
	}

	// z = k - s_i * c
	z := k.Sub(secret.Mul(challenge))

	return Signature{
		R: R,
		Z: z,
	}
}

// ensures that the we correctly turn secp256k1 points into eth addresses
func TestPointToAddressCorrect(t *testing.T) {
	zero := (&saferith.Nat{}).SetUint64(2)
	crv := curve.Secp256k1{}
	sk := crv.NewScalar()
	sk.SetNat(zero)

	g := sk.ActOnBase()

	ethAdd, err := eth.PointToAddress(g)
	require.NoError(t, err)

	add := fmt.Sprintf("%x", ethAdd)
	expected := "2b5ad5c4795c026514f8317c7a215e218dccd6cf"
	require.Equal(t, expected, add)
}

func TestPointMarshalling(t *testing.T) {
	t.Skip("this test is not relevant, until we receive a smart contract we can match it against.")
	_, pk := genSpecificKeyPair(t)
	binrep, err := marshalPointForContract(pk)
	require.NoError(t, err)

	expected := "22178267bd659068c413737725507b2edabfa74b032882a8dacb806378ee660101"
	actual := fmt.Sprintf("%x", binrep)
	require.Equal(t, expected, actual)

	// 2:
	zero := (&saferith.Nat{}).SetUint64(2)
	crv := curve.Secp256k1{}
	sk := crv.NewScalar()
	sk.SetNat(zero)

	g := sk.ActOnBase()

	expected = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee500"
	binrep, err = marshalPointForContract(g)
	require.NoError(t, err)
	actual = fmt.Sprintf("%x", binrep)
	require.Equal(t, expected, actual)
}

func TestChallengeMaking(t *testing.T) {
	t.Skip("this test is not relevant, until we receive a smart contract we can match it against.")
	_, pk := genSpecificKeyPair(t)

	c, err := challengeHash(pk, pk, []byte{1, 2, 3, 4, 5})
	require.NoError(t, err)

	expected := "b9cb68e0791880df291cc7dc095320abf9905f81f7f3f587fade4fb192b2bfd6"
	actual := fmt.Sprintf("%x", c)

	require.Equal(t, expected, actual)

	two := (&saferith.Nat{}).SetUint64(2)
	sk2 := curve.Secp256k1{}.NewScalar().SetNat(two)
	R := sk2.ActOnBase()
	c, err = challengeHash(R, pk, []byte{1, 2, 3, 4, 5})
	require.NoError(t, err)

	expected = "f7dcf73cfaaff1f2f43d6755ad4f99ea192cfeee77595fcace118270713174b7"
	actual = fmt.Sprintf("%x", c)
	require.Equal(t, expected, actual)
}

func genSpecificKeyPair(t *testing.T) (curve.Scalar, curve.Point) {
	nat := &saferith.Nat{}
	tmpSk, ok := big.NewInt(0).SetString("113573023772299159856332917461260299670834135398442378301276451420454662821454", 10)
	require.True(t, ok)

	n := nat.SetBig(tmpSk, tmpSk.BitLen())

	crv := curve.Secp256k1{}
	sk := crv.NewScalar()
	sk.SetNat(n)

	pk := sk.ActOnBase()
	return sk, pk
}

func TestBasic(t *testing.T) {
	var secret curve.Scalar
	var public curve.Point
	count := 50 // number of attempts to find a valid public key
	for i := 0; i < count; i++ {
		secret = sample.Scalar(rand.Reader, curve.Secp256k1{})
		public = secret.ActOnBase()
		if PublicKeyValidForContract(public) {
			break
		}
		if i == count-1 {
			t.Fatalf("could not find a valid public key after %d attempts", count)
		}
	}

	msgHash := [32]byte{1, 2, 3, 4, 5}

	sig := SignEcSchnorr(secret, msgHash[:])
	assert.NoError(t, sig.Verify(public, msgHash[:]), "expected valid signature")

	consig, err := sig.ToContractSig(public, msgHash[:])
	assert.NoError(t, err, "expected valid contract signature")

	fmt.Println(consig)
}

func checkOutput(t *testing.T, rounds []round.Session, public curve.Point, m []byte) {
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, Signature{}, resultRound.Result, "expected signature result")
		signature := resultRound.Result.(Signature)
		assert.NoError(t, signature.Verify(public, m), "expected valid signature")
	}

	r := rounds[0]
	resultRound := r.(*round.Output)
	signature := resultRound.Result.(Signature)

	res, err := signature.ToContractSig(public, m)
	require.NoError(t, err, "expected valid contract signature")
	fmt.Println(res)
}

func TestSign(t *testing.T) {
	group := curve.Secp256k1{}

	N := 5
	threshold := 2

	partyIDs := test.PartyIDs(N)

	f, publicKey := DKGShares(group, threshold)

	steak := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]curve.Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar(group))
	}

	verificationShares := make(map[party.ID]curve.Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = privateShares[id].ActOnBase()
	}

	var newPublicKey curve.Point
	rounds := make([]round.Session, 0, N)
	for _, id := range partyIDs {
		result := &keygen.Config{
			ID:                 id,
			Threshold:          threshold,
			PublicKey:          publicKey,
			PrivateShare:       privateShares[id],
			VerificationShares: party.NewPointMap(verificationShares),
			ChainKey:           chainKey,
		}

		if newPublicKey == nil {
			newPublicKey = result.PublicKey
		}

		// ensuring shuffling the order of party IDs doesn't affect signing process.
		shuffledIds := shuffleIds(partyIDs)

		r, err := StartSignCommon(false, result, shuffledIds, steak[:])(test.TestTrackingID.ToByteString())
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	checkOutput(t, rounds, newPublicKey, steak[:])
}

func DKGShares(group curve.Secp256k1, threshold int) (*polynomial.Polynomial, curve.Point) {
	for {
		secret := sample.Scalar(rand.Reader, group)
		f := polynomial.NewPolynomial(group, threshold, secret)
		publicKey := secret.ActOnBase()

		if PublicKeyValidForContract(publicKey) {
			return f, publicKey
		}
	}
}

func checkOutputTaproot(t *testing.T, rounds []round.Session, public taproot.PublicKey, m []byte) {
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, taproot.Signature{}, resultRound.Result, "expected taproot signature result")
		signature := resultRound.Result.(taproot.Signature)
		assert.True(t, public.Verify(signature, m), "expected valid signature")
	}
}

func TestSignTaproot(t *testing.T) {
	group := curve.Secp256k1{}
	N := 5
	threshold := 2

	partyIDs := test.PartyIDs(N)

	secret := sample.Scalar(rand.Reader, group)
	publicPoint := secret.ActOnBase()
	if !publicPoint.(*curve.Secp256k1Point).HasEvenY() {
		secret.Negate()
	}
	f := polynomial.NewPolynomial(group, threshold, secret)
	publicKey := taproot.PublicKey(publicPoint.(*curve.Secp256k1Point).XBytes())
	steakHash := sha256.New()
	_, _ = steakHash.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	steak := steakHash.Sum(nil)
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]*curve.Secp256k1Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar(group)).(*curve.Secp256k1Scalar)
	}

	verificationShares := make(map[party.ID]*curve.Secp256k1Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = privateShares[id].ActOnBase().(*curve.Secp256k1Point)
	}

	var newPublicKey []byte
	rounds := make([]round.Session, 0, N)
	for _, id := range partyIDs {
		result := &keygen.TaprootConfig{
			ID:                 id,
			Threshold:          threshold,
			PublicKey:          publicKey,
			PrivateShare:       privateShares[id],
			VerificationShares: verificationShares,
		}
		result, _ = result.DeriveChild(1)
		if newPublicKey == nil {
			newPublicKey = result.PublicKey
		}
		tapRootPublicKey, err := curve.Secp256k1{}.LiftX(newPublicKey)
		genericVerificationShares := make(map[party.ID]curve.Point)
		for k, v := range result.VerificationShares {
			genericVerificationShares[k] = v
		}
		require.NoError(t, err)
		normalResult := &keygen.Config{
			ID:                 result.ID,
			Threshold:          result.Threshold,
			PrivateShare:       result.PrivateShare,
			PublicKey:          tapRootPublicKey,
			VerificationShares: party.NewPointMap(genericVerificationShares),
		}
		r, err := StartSignCommon(true, normalResult, partyIDs, steak)(test.TestTrackingID.ToByteString())
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	checkOutputTaproot(t, rounds, newPublicKey, steak)
}

func genKeyPair(group curve.Curve) (curve.Scalar, curve.Point) {
	for range 50 {
		secret := sample.Scalar(rand.Reader, group)
		publicKey := secret.ActOnBase()

		if PublicKeyValidForContract(publicKey) {
			return secret, publicKey
		}
	}

	panic("could not find a valid key pair")
}

func TestSigMarshal(t *testing.T) {
	secret, public := genKeyPair(curve.Secp256k1{})

	msgHash := [32]byte{1, 2, 3, 4, 5}

	sig := SignEcSchnorr(secret, msgHash[:])
	assert.NoError(t, sig.Verify(public, msgHash[:]), "expected valid signature")

	// Marshal the signature to bytes
	bts, err := sig.MarshalBinary()
	require.NoError(t, err)

	fmt.Printf("Marshalled signature: %x\n", bts)

	// Unmarshal the bytes back to a signature
	unmarshalledSig := Signature{}

	err = unmarshalledSig.UnmarshalBinary(curve.Secp256k1{}, bts)
	require.NoError(t, err)

	// Verify that the unmarshalled signature is valid
	assert.NoError(t, unmarshalledSig.Verify(public, msgHash[:]), "expected valid unmarshalled signature")
}

func shuffleIds(partyIDs []party.ID) []party.ID {
	shuffledIds := party.NewIDSlice(partyIDs)
	mathrand.Shuffle(len(shuffledIds), func(i, j int) {
		shuffledIds[i], shuffledIds[j] = shuffledIds[j], shuffledIds[i]
	})

	return shuffledIds
}
