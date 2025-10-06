package sign

import (
	"fmt"

	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/protocol"
	"github.com/xlabs/multi-party-sig/pkg/round"
	"github.com/xlabs/multi-party-sig/protocols/frost/keygen"
	common "github.com/xlabs/tss-common"
)

const (
	// Frost Sign with Threshold.
	protocolID        = string(common.ProtocolFROSTSign)
	protocolIDTaproot = string(common.ProtocolFROSTSign) + "-taproot"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

func StartSignCommon(taproot bool, result *keygen.Config, signers []party.ID, messageHash []byte) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		if !result.ValidateBasic() {
			return nil, fmt.Errorf("invalid keygen result")
		}

		// Since the config might be used concurrently in multiple signing sessions, and this session might
		// mutate the config (for example, by applying `scalar.Act(pk)`),
		// we clone it here to be safe.
		configCopy, err := result.Clone()
		if err != nil {
			return nil, fmt.Errorf("sign.StartSign: failed to clone keygen config: %w", err)
		}

		info := round.Info{
			FinalRoundNumber: protocolRounds,
			SelfID:           configCopy.ID,
			PartyIDs:         party.NewIDSlice(signers), // ensures sorted order
			Threshold:        configCopy.Threshold,
			Group:            configCopy.PublicKey.Curve(),
			ProtocolID:       protocolID,
			TrackingID:       &common.TrackingID{},
		}

		if err := info.TrackingID.FromString(string(sessionID)); err != nil {
			return nil, fmt.Errorf("sign.StartSign: %w", err)
		}

		if taproot {
			info.ProtocolID = protocolIDTaproot
		} else {
			info.ProtocolID = protocolID
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("sign.StartSign: %w", err)
		}
		return &round1{
			Helper:  helper,
			taproot: taproot,
			M:       messageHash,
			Y:       configCopy.PublicKey,
			YShares: configCopy.VerificationShares.Points,
			s_i:     configCopy.PrivateShare,
		}, nil
	}
}
