package cmp

import (
	"fmt"

	"github.com/xlabs/multi-party-sig/pkg/ecdsa"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/pool"
	"github.com/xlabs/multi-party-sig/pkg/protocol"
	"github.com/xlabs/multi-party-sig/pkg/round"
	"github.com/xlabs/multi-party-sig/protocols/cmp/config"
	"github.com/xlabs/multi-party-sig/protocols/cmp/keygen"
	"github.com/xlabs/multi-party-sig/protocols/cmp/sign"
	common "github.com/xlabs/tss-common"
)

// Config represents the stored state of a party who participated in a successful `Keygen` protocol.
// It contains secret key material and should be safely stored.
type Config = config.Config

// EmptyConfig creates an empty Config with a fixed group, ready for unmarshalling.
//
// This needs to be used for unmarshalling, otherwise the points on the curve can't
// be decoded.
func EmptyConfig(group curve.Curve) *Config {
	return &Config{
		Group: group,
	}
}

// Keygen generates a new shared ECDSA key over the curve defined by `group`. After a successful execution,
// all participants posses a unique share of this key, as well as auxiliary parameters required during signing.
//
// For better performance, a `pool.Pool` can be provided in order to parallelize certain steps of the protocol.
// Returns *cmp.Config if successful.
func Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) protocol.StartFunc {
	info := round.Info{
		ProtocolID:       string(keygen.ProtocolName),
		FinalRoundNumber: keygen.Rounds,
		SelfID:           selfID,
		PartyIDs:         participants,
		Threshold:        threshold,
		Group:            group,
	}
	return keygen.Start(info, pl, nil)
}

// Refresh allows the parties to refresh all existing cryptographic keys from a previously generated Config.
// The group's ECDSA public key remains the same, but any previous shares are rendered useless.
// Returns *cmp.Config if successful.
func Refresh(config *Config, pl *pool.Pool) protocol.StartFunc {
	info := round.Info{
		ProtocolID:       "cmp/refresh-threshold",
		FinalRoundNumber: keygen.Rounds,
		SelfID:           config.ID,
		PartyIDs:         config.PartyIDs(),
		Threshold:        config.Threshold,
		Group:            config.Group,
	}
	return keygen.Start(info, pl, config)
}

// Sign generates an ECDSA signature for `messageHash` among the given `signers`.
// Returns *ecdsa.Signature if successful.
func Sign(config *Config, signers []party.ID, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	return sign.StartSign(config, signers, messageHash, pl)
}

// TODO: The following is almost a duplicate of frost.Secp256k1SignatureTranslate:

var (
	ErrNilSignatureData = fmt.Errorf("signature data is nil")
	ErrEmptySignatureS  = fmt.Errorf("signature.S data is empty")
	ErrEmptySignatureR  = fmt.Errorf("signature.R data is empty")
)

// used to convert a common.SignatureData to a frost.Signature.
// frost signature can be turned to contractSignature which can be used by ethereum contracts.
func Secp256k1SignatureTranslate(sig *common.SignatureData) (ecdsa.Signature, error) {
	// TODO: This is similar to FROST's implementation. Consider refactoring to avoid code duplication.
	if sig == nil {
		return ecdsa.Signature{}, ErrNilSignatureData
	}

	if sig.S == nil {
		return ecdsa.Signature{}, ErrEmptySignatureS
	}

	if sig.R == nil {
		return ecdsa.Signature{}, ErrEmptySignatureR
	}

	group := curve.Secp256k1{}

	z, err := group.UnmarshalScalar(sig.S)
	if err != nil {
		return ecdsa.Signature{}, fmt.Errorf("failed to unmarshal S: %w", err)
	}

	R, err := group.UnmarshalPoint(sig.R)
	if err != nil {
		return ecdsa.Signature{}, fmt.Errorf("failed to unmarshal R: %w", err)
	}

	return ecdsa.Signature{
		R: R,
		S: z,
	}, nil
}
