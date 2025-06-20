package sign

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/cronokirby/saferith"
	"github.com/xlabs/multi-party-sig/pkg/eth"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"golang.org/x/crypto/sha3"
)

// messageHash is a wrapper around bytes to provide some domain separation.
type messageHash []byte

// WriteTo makes messageHash implement the io.WriterTo interface.
func (m messageHash) WriteTo(w io.Writer) (int64, error) {
	if m == nil {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := w.Write(m)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (messageHash) Domain() string {
	return "messageHash"
}

// Signature represents the result of a Schnorr signature.
//
// This signature claims to satisfy:
//
//	z * G = R + H(R, Y, m) * Y
//
// for a public key Y.
type Signature struct {
	// R is the commitment point.
	R curve.Point
	// z is the response scalar.
	Z curve.Scalar
}

func marshalPointForContract(p curve.Point) ([]byte, error) {
	bts, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}

	contractStyleMarshal := make([]byte, len(bts))
	copy(contractStyleMarshal, bts[1:])
	contractStyleMarshal[len(bts)-1] = bts[0] - 2

	return contractStyleMarshal, nil
}

func (s Signature) ToContractSig(pk curve.Point, msg []byte) (ContractSig, error) {
	sigBin, err := s.Z.MarshalBinary()
	if err != nil {
		return ContractSig{}, err
	}

	rAddress, err := eth.PointToAddress(s.R)
	if err != nil {
		return ContractSig{}, err
	}

	pkBin, err := marshalPointForContract(pk)
	if err != nil {
		return ContractSig{}, err
	}

	consig := ContractSig{
		PkX:       [32]byte(pkBin[:32]),
		PkYParity: pkBin[32],
		S:         (&big.Int{}).SetBytes(sigBin),
		M:         (&big.Int{}).SetBytes(msg),
		R:         s.R,
		Address:   rAddress,
	}

	return consig, nil
}

// returns {s, R} one after the other inside a byte slice.
// s is a scalar of 32 bytes, padded with leading zeros.
// R is a point in compact marshal form of 33 bytes
func (s Signature) MarshalBinary() ([]byte, error) {
	sigBin, err := s.Z.MarshalBinary()
	if err != nil {
		return nil, err
	}

	rBin, err := s.R.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if len(sigBin) > 32 {
		return nil, fmt.Errorf("signature scalar is too long: expected 32 bytes, got %d", len(sigBin))
	}

	b := bytes.NewBuffer(nil)
	if _, err := b.Write(LeftPadBytes(sigBin, 32)); err != nil {
		return nil, err
	}

	if _, err := b.Write(LeftPadBytes(rBin, 33)); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func EmptySignature(c curve.Curve) (Signature, error) {
	if c == nil {
		return Signature{}, fmt.Errorf("curve cannot be nil")
	}
	return Signature{
		R: c.NewPoint(),
		Z: c.NewScalar(),
	}, nil
}

func (s *Signature) UnmarshalBinary(bts []byte) error {
	if s == nil {
		return fmt.Errorf("cannot unmarshal into nil Signature")
	}
	if s.R == nil || s.Z == nil {
		return fmt.Errorf("cannot unmarshal into empty Signature")
	}

	if len(bts) <= 32 {
		return fmt.Errorf("invalid length for signature binary: expected at least 32 bytes, got %d", len(bts))
	}

	if err := s.Z.UnmarshalBinary(bts[:32]); err != nil {
		return fmt.Errorf("failed to unmarshal S scalar: %w", err)
	}

	if err := s.R.UnmarshalBinary(bts[32:]); err != nil {
		return fmt.Errorf("failed to unmarshal R point: %w", err)
	}

	return nil
}

type ContractSig struct {
	PkX       [32]byte
	PkYParity uint8
	M         *big.Int // Message Hash

	S       *big.Int
	R       curve.Point
	Address eth.EthAddress
}

func Bytes2Hex(d []byte) string {
	return hex.EncodeToString(d)
}

func LeftPadBytes(slice []byte, l int) []byte {
	if l <= len(slice) {
		return slice
	}

	padded := make([]byte, l)
	copy(padded[l-len(slice):], slice)

	return padded
}

func (s ContractSig) String() string {
	b := strings.Builder{}

	b.WriteString("ContractSig{\n")
	b.WriteString("  pkX                : 0x" + Bytes2Hex(s.PkX[:]) + "\n")
	b.WriteString("  pkyparity          : " + strconv.FormatUint(uint64(s.PkYParity), 10) + "\n")
	b.WriteString("  msghash            : 0x" + Bytes2Hex(LeftPadBytes(s.M.Bytes(), 32)) + "\n")
	b.WriteString("  s                  : 0x" + Bytes2Hex(LeftPadBytes(s.S.Bytes(), 32)) + "\n")
	b.WriteString("  nonceTimesGAddress : 0x" + Bytes2Hex(s.Address[:]) + "\n")
	b.WriteString("}\n")

	return b.String()
}

func PublicKeyValidForContract(pk curve.Point) bool {
	return !pk.XScalar().IsOverHalfOrder() // TODO: need more checks to match with smart contract.
}

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
