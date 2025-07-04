package test

import (
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/round"
	common "github.com/xlabs/tss-common"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
)

// Rule describes various hooks that can be applied to a protocol execution.
type Rule interface {
	// ModifyBefore modifies r before r.Finalize() is called.
	ModifyBefore(r round.Session)
	// ModifyAfter modifies rNext, which is the round returned by r.Finalize().
	ModifyAfter(rNext round.Session)
	// ModifyContent modifies content for the message that is delivered in rNext.
	ModifyContent(rNext round.Session, to party.ID, content round.Content)
}

func Rounds(rounds []round.Session, rule Rule) (error, bool) {
	var (
		err       error
		roundType reflect.Type
		errGroup  errgroup.Group
		N         = len(rounds)
		out       = make(chan common.ParsedMessage, N*(N+1))
	)

	if roundType, err = checkAllRoundsSame(rounds); err != nil {
		return err, false
	}

	mtx := sync.Mutex{}

	// get the second set of messages
	for id := range rounds {
		idx := id
		r := rounds[idx]
		errGroup.Go(func() error {
			mtx.Lock()
			defer mtx.Unlock()

			var rNew, rNewReal round.Session
			if rule != nil {
				rReal := getRound(r)
				rule.ModifyBefore(rReal)
				outFake := make(chan common.ParsedMessage, N+1)
				// Rounds should finish at this point, so we ensure that
				// they utilise the CanFinalize method correctly.
				if !r.CanFinalize() {
					return errors.New("cannot finalize")
				}

				rNew, err = r.Finalize(outFake)
				close(outFake)
				rNewReal = getRound(rNew)
				rule.ModifyAfter(rNewReal)
				for msg := range outFake {
					var to party.ID
					if msg.GetTo() != nil {
						to = party.FromTssID(msg.GetTo())
					}

					rule.ModifyContent(rNewReal, to, getContent(msg.Content()))
					out <- msg
				}
			} else {
				if !r.CanFinalize() {
					return errors.New("cannot finalize")
				}
				rNew, err = r.Finalize(out)
			}

			if err != nil {
				return err
			}

			if rNew != nil {
				rounds[idx] = rNew
			}
			return nil
		})
	}
	if err = errGroup.Wait(); err != nil {
		return err, false
	}
	close(out)

	// Check that all rounds are the same type
	if roundType, err = checkAllRoundsSame(rounds); err != nil {
		return err, false
	}
	if roundType.String() == reflect.TypeOf(&round.Output{}).String() {
		return nil, true
	}
	if roundType.String() == reflect.TypeOf(&round.Abort{}).String() {
		return nil, true
	}

	for msg := range out {
		// Sending mechanism for testing...
		for _, r := range rounds {
			cntnt := proto.CloneOf(msg.Content())

			tid := proto.CloneOf(msg.WireMsg().TrackingID)

			r := r
			if party.FromTssID(msg.GetFrom()) == r.SelfID() || round.Number(msg.Content().RoundNumber()) != r.Number() {
				continue
			}

			errGroup.Go(func() error {

				m := round.Message{
					From:       party.FromTssID(msg.GetFrom()),
					To:         "",
					Broadcast:  false,
					Content:    cntnt,
					TrackingID: tid,
				}

				mtx.Lock()
				defer mtx.Unlock()

				if msg.IsBroadcast() {
					m.Broadcast = true

					b, ok := r.(round.BroadcastRound)
					if !ok {
						return errors.New("broadcast message but not broadcast round")
					}

					if err = b.StoreBroadcastMessage(m); err != nil {
						return err
					}
				} else {
					m.To = party.FromTssID(msg.GetTo())

					if m.To == "" || m.To == r.SelfID() {
						if err = r.VerifyMessage(m); err != nil {
							return err
						}
						if err = r.StoreMessage(m); err != nil {
							return err
						}
					}
				}

				return nil
			})
		}
		if err = errGroup.Wait(); err != nil {
			return err, false
		}
	}

	return nil, false
}

func checkAllRoundsSame(rounds []round.Session) (reflect.Type, error) {
	var t reflect.Type
	for _, r := range rounds {
		rReal := getRound(r)
		t2 := reflect.TypeOf(rReal)
		if t == nil {
			t = t2
		} else if t != t2 {
			return t, fmt.Errorf("two different rounds: %s %s", t, t2)
		}
	}
	return t, nil
}

func getRound(outerRound round.Session) round.Session {
	return outerRound
}

func getContent(outerContent round.Content) round.Content {
	return outerContent
}
