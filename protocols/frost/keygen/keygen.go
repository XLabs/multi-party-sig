package keygen

import (
	"fmt"
	"maps"

	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/protocol"
	"github.com/xlabs/multi-party-sig/pkg/round"
	common "github.com/xlabs/tss-common"
)

const (
	// Frost KeyGen with Threshold.
	protocolID        = "frost/keygen-threshold"
	protocolIDTaproot = "frost/keygen-threshold-taproot"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

// These assert that our rounds implement the round.Round interface.
var (
	_ round.Round = (*round1)(nil)
	_ round.Round = (*round2)(nil)
	_ round.Round = (*round3)(nil)
)

func StartKeygenCommon(taproot bool, group curve.Curve, participants []party.ID, threshold int, selfID party.ID, privateShare curve.Scalar, publicKey curve.Point, verificationShares map[party.ID]curve.Point) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			FinalRoundNumber: protocolRounds,
			SelfID:           selfID,
			PartyIDs:         participants,
			Threshold:        threshold,
			Group:            group,
			TrackingID:       &common.TrackingID{},
		}
		if err := info.TrackingID.FromString(string(sessionID)); err != nil {
			return nil, fmt.Errorf("keygen.Start: %w", err)
		}

		if threshold < 1 {
			return nil, fmt.Errorf("threshold must be at least 1")
		}

		if threshold >= len(participants) {
			// since threshold+1 is the number of participants needed to make a signature together,
			// we need to ensure that threshold < len(participants).
			return nil, fmt.Errorf("threshold cannot be greater or equal to the number of participants")
		}

		if taproot {
			info.ProtocolID = protocolIDTaproot
		} else {
			info.ProtocolID = protocolID
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("keygen.StartKeygen: %w", err)
		}

		verificationSharesCopy := make(map[party.ID]curve.Point, len(participants))
		maps.Copy(verificationSharesCopy, verificationShares)

		refresh := true
		if privateShare == nil || publicKey == nil {
			refresh = false
			privateShare = group.NewScalar()
			publicKey = group.NewPoint()
			for _, k := range participants {
				verificationSharesCopy[k] = group.NewPoint()
			}
		}

		return &round1{
			Helper:             helper,
			taproot:            taproot,
			threshold:          threshold,
			refresh:            refresh,
			privateShare:       privateShare,
			verificationShares: verificationSharesCopy,
			publicKey:          publicKey,
		}, nil
	}
}
