package sign

import (
	"errors"

	"github.com/xlabs/multi-party-sig/pkg/paillier"
	zkenc "github.com/xlabs/multi-party-sig/pkg/zk/enc"
	common "github.com/xlabs/tss-common"
)

func makeBroadcast2(k, g *paillier.Ciphertext) (*Broadcast2, error) {
	if k == nil || g == nil {
		return nil, errors.New("invalid ciphertexts")
	}

	kbytes, err := k.MarshalBinary()
	if err != nil {
		return nil, err
	}
	gbytes, err := g.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &Broadcast2{
		K: kbytes,
		G: gbytes,
	}, nil
}

// GetProtocol implements round.Content.
func (b *Broadcast2) GetProtocol() common.ProtocolType {
	return common.ProtocolECDSA // TODO: Should we add some modifier? stating this is ecdsa:sign?
}

func (x *Broadcast2) ValidateBasic() bool {
	return x != nil && len(x.K) > 0 && len(x.G) > 0
}

// Reliable implements round.ReliableBroadcastContent.
func (b *Broadcast2) Reliable() bool {
	return true
}

// RoundNumber implements round.Content.
func (x *Broadcast2) RoundNumber() int {
	return 2
}

func (x *Broadcast2) UnmarshalContent() (*paillier.Ciphertext, *paillier.Ciphertext, error) {
	k := &paillier.Ciphertext{}
	if err := k.UnmarshalBinary(x.K); err != nil {
		return nil, nil, err
	}

	g := &paillier.Ciphertext{}
	if err := g.UnmarshalBinary(x.G); err != nil {
		return nil, nil, err
	}

	return k, g, nil
}

func MakeMessage2(proofEnc *zkenc.Proof) (*Message2, error) {
	proofBytes, err := proofEnc.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &Message2{
		ProofEnc: proofBytes,
	}, nil
}

// GetProtocol implements round.Content.
func (b *Message2) GetProtocol() common.ProtocolType {
	return common.ProtocolECDSA // TODO: Should we add some modifier? stating this is ecdsa:sign?
}

func (x *Message2) ValidateBasic() bool {
	return x != nil && len(x.ProofEnc) > 0
}

// Reliable implements round.ReliableBroadcastContent.
func (b *Message2) Reliable() bool {
	return false
}

// RoundNumber implements round.Content.
func (x *Message2) RoundNumber() int {
	return 2
}

func (x *Message2) UnmarshalContent() (*zkenc.Proof, error) {
	proof := &zkenc.Proof{}
	if err := proof.UnmarshalBinary(x.ProofEnc); err != nil {
		return nil, err
	}

	return proof, nil
}
