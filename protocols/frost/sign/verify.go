package sign

import (
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/xlabs/multi-party-sig/pkg/eth"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"golang.org/x/crypto/sha3"
)

// Verify checks if a signature equation actually holds.
//
// Note that m is the hash of a message, and not the message itself.
func (sig Signature) Verify(public curve.Point, m []byte) error {
	r, err := eth.PointToAddress(sig.R)
	if err != nil {
		return err
	}

	challenge, err := intoEVMCompatibleChallenge(sig.R, public, messageHash(m))
	if err != nil {
		return err
	}

	// expected := challenge.Act(public) // ePK = -exG?
	ePK := challenge.Act(public)
	// expected = expected.Add(sig.R)    // R + exG =? kG + exG == sG
	sG := sig.Z.ActOnBase() // sG = zG

	actual := ePK.Add(sG) // where  s = k-s_iC.
	// ePK + sG = e(xG) + (k+xe)G

	actualAddress, err := eth.PointToAddress(actual)
	if err != nil {
		return err
	}

	if r != actualAddress {
		return fmt.Errorf("signature verification failed: %x != %x", r, actualAddress)
	}

	return nil //actual.Equal(sig.R)
}

// this function is responsible for creating the challegne scalar for schnorr signatures.
// that is Hash(R,PK, msgDigest). While usually R is nonce * G, in the case of smart contracts,
// R is an eth address (so we can use it with the ecrecover function in EVM.).
func intoEVMCompatibleChallenge(R, pk curve.Point, msgHash []byte) (curve.Scalar, error) {
	sumhash, err := challengeHash(R, pk, msgHash)
	if err != nil {
		return nil, err
	}

	nat := new(saferith.Nat).SetBytes(sumhash)
	c := pk.Curve().NewScalar().SetNat(nat)

	return c, nil
}

func challengeHash(R curve.Point, pk curve.Point, msgHash []byte) ([]byte, error) {
	hsh := sha3.NewLegacyKeccak256()

	pkbts, err := marshalPointForContract(pk)
	if err != nil {
		return nil, err
	}

	if _, err := hsh.Write(pkbts); err != nil {
		return nil, err
	}

	if _, err := hsh.Write(msgHash); err != nil {
		return nil, err
	}

	addressR, err := eth.PointToAddress(R)
	if err != nil {
		return nil, err
	}

	if _, err := hsh.Write(addressR[:]); err != nil {
		return nil, err
	}

	return hsh.Sum(nil), nil
}
