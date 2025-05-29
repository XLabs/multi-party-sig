package round

import (
	"github.com/xlabs/multi-party-sig/pkg/party"
	common "github.com/xlabs/tss-common"
)

// Content represents the message, either broadcast or P2P returned by a round
// during finalization.
type Content common.MessageContent

// BroadcastContent wraps a Content, but also indicates whether this content
// requires reliable broadcast.
type BroadcastContent interface {
	Content
	// Reliable() bool
}

// These structs can be embedded in a broadcast message as a way of
// 1. implementing BroadcastContent
// 2. indicate to the handler whether the content should be reliably broadcast
// When non-unanimous halting is acceptable, we can use the echo broadcast.
type (
	ReliableBroadcastContent struct{}
	NormalBroadcastContent   struct{}
)

func (ReliableBroadcastContent) Reliable() bool { return true }
func (NormalBroadcastContent) Reliable() bool   { return false }

type Message struct {
	From, To   party.ID
	Broadcast  bool
	Content    Content
	TrackingID *common.TrackingID
}

func (m *Message) ToParsed() common.ParsedMessage {
	meta := common.MessageRouting{
		From:        m.From.ToTssPartyID(),
		To:          []*common.PartyID{m.To.ToTssPartyID()},
		IsBroadcast: m.Broadcast,
	}

	msg := common.NewMessageWrapper(meta, m.Content, m.TrackingID)
	return common.NewMessage(meta, m.Content, msg)
}

func IsFor(m common.ParsedMessage, id party.ID) bool {
	if party.FromTssID(m.GetFrom()) == id {
		return false
	}

	if m.IsBroadcast() || m.GetTo() == nil {
		return true
	}

	for _, to := range m.GetTo() {
		if party.FromTssID(to) == id {
			return true
		}
	}

	return false
}
