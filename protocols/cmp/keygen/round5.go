package keygen

import (
	"errors"
	"fmt"

	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/round"
	"github.com/xlabs/multi-party-sig/protocols/cmp/config"
	common "github.com/xlabs/tss-common"
)

var _ round.Round = (*round5)(nil)

type round5 struct {
	*round4
	UpdatedConfig *config.Config

	validSchnorrResp map[party.ID]bool
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - verify all Schnorr proof for the new ecdsa share.
func (r *round5) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*Broadcast5)
	if !ok || !body.ValidateBasic() {
		return round.ErrInvalidContent
	}

	schnorrResponse, err := body.UnmarshalContent(r.Group())
	if err != nil {
		return fmt.Errorf("failed to unmarshal Schnorr response: %w", err)
	}

	if !schnorrResponse.IsValid() {
		return round.ErrNilFields
	}

	if !schnorrResponse.Verify(r.HashForID(from),
		r.UpdatedConfig.Public[from].ECDSA,
		r.SchnorrCommitments[from], nil) {
		return errors.New("failed to validate schnorr proof for received share")
	}

	r.validSchnorrResp[from] = true

	return nil
}

// VerifyMessage implements round.Round.
func (round5) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round5) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round5) Finalize(chan<- common.ParsedMessage) (round.Session, error) {
	return r.ResultRound(r.UpdatedConfig), nil
}

func (r *round5) CanFinalize() bool {
	t := r.Threshold() + 1
	if len(r.validSchnorrResp) < t {
		return false
	}

	// should ensure each party sent validSchnorrResp
	for _, p := range r.PartyIDs() {
		if !r.validSchnorrResp[p] {
			return false
		}
	}

	return true
}

// MessageContent implements round.Round.
func (r *round5) MessageContent() round.Content { return nil }

// BroadcastContent implements round.BroadcastRound.
func (r *round5) BroadcastContent() round.BroadcastContent {
	return &Broadcast5{
		SchnorrResponse: nil,
	}
}

// Number implements round.Round.
func (round5) Number() round.Number { return 5 }
