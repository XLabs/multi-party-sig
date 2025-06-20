package round

import (
	"github.com/xlabs/multi-party-sig/pkg/party"
	common "github.com/xlabs/tss-common"
)

// Abort is an empty round containing a list of parties who misbehaved.
type Abort struct {
	*Helper
	Culprits []party.ID
	Err      error
}

func (Abort) VerifyMessage(Message) error                              { return nil }
func (Abort) StoreMessage(Message) error                               { return nil }
func (r *Abort) Finalize(chan<- common.ParsedMessage) (Session, error) { return r, nil }
func (Abort) MessageContent() Content                                  { return nil }
func (Abort) Number() Number                                           { return 0 }
func (r *Abort) CanFinalize() bool                                     { return false }
