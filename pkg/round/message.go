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
	Reliable() bool
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
	var to *common.PartyID = nil
	if !m.Broadcast {
		to = m.To.ToTssPartyID()
	}

	meta := common.MessageRouting{
		From: m.From.ToTssPartyID(),
		To:   to,
	}

	msg := common.NewMessageWrapper(meta, m.Content, m.TrackingID)
	return common.NewMessage(meta, m.Content, msg)
}
