package protocol

import (
	"fmt"

	"github.com/xlabs/multi-party-sig/pkg/hash"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/round"
)

type Message struct {
	// SSID is a byte string which uniquely identifies the session this message belongs to.
	SSID []byte
	// From is the party.ID of the sender
	From party.ID
	// To is the intended recipient for this message. If To == "", then the message should be sent to all.
	To party.ID
	// Protocol identifies the protocol this message belongs to
	Protocol string
	// RoundNumber is the index of the round this message belongs to
	RoundNumber round.Number
	// Data is the actual content consumed by the round.
	Data []byte
	// Broadcast indicates whether this message should be reliably broadcast to all participants.
	Broadcast bool
	// BroadcastVerification is the hash of all messages broadcast by the parties,
	// and is included in all messages in the round following a broadcast round.
	BroadcastVerification []byte
}

// String implements fmt.Stringer.
func (m Message) String() string {
	return fmt.Sprintf("message: round %d, from: %s, to %v, protocol: %s", m.RoundNumber, m.From, m.To, m.Protocol)
}

// IsFor returns true if the message is intended for the designated party.
func (m Message) IsFor(id party.ID) bool {
	if m.From == id {
		return false
	}
	return m.To == "" || m.To == id
}

// Hash returns a 64 byte hash of the message content, including the headers.
// Can be used to produce a signature for the message.
func (m *Message) Hash() []byte {
	var broadcast byte
	if m.Broadcast {
		broadcast = 1
	}
	h := hash.New(
		hash.BytesWithDomain{TheDomain: "SSID", Bytes: m.SSID},
		m.From,
		m.To,
		hash.BytesWithDomain{TheDomain: "Protocol", Bytes: []byte(m.Protocol)},
		m.RoundNumber,
		hash.BytesWithDomain{TheDomain: "Content", Bytes: m.Data},
		hash.BytesWithDomain{TheDomain: "Broadcast", Bytes: []byte{broadcast}},
		hash.BytesWithDomain{TheDomain: "BroadcastVerification", Bytes: m.BroadcastVerification},
	)
	return h.Sum()
}
