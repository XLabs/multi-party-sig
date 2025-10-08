package sign

import (
	"errors"

	"github.com/xlabs/multi-party-sig/internal/marshal"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/paillier"
	zkaffg "github.com/xlabs/multi-party-sig/pkg/zk/affg"
	zkenc "github.com/xlabs/multi-party-sig/pkg/zk/enc"
	zklogstar "github.com/xlabs/multi-party-sig/pkg/zk/logstar"
	common "github.com/xlabs/tss-common"
)

// -- round 2 --

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
	return ProtocolName
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
	proofBytes, err := marshal.Encode(proofEnc)
	if err != nil {
		return nil, err
	}

	return &Message2{
		ProofEnc: proofBytes,
	}, nil
}

// GetProtocol implements round.Content.
func (b *Message2) GetProtocol() common.ProtocolType {
	return ProtocolName
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
	if err := marshal.Decode(x.ProofEnc, proof); err != nil {
		return nil, err
	}

	return proof, nil
}

// -- round 3 ---
func makeBroadcast3(bigGammaShare curve.Point) (*Broadcast3, error) {
	if bigGammaShare == nil {
		return nil, errors.New("invalid big gamma share")
	}
	bts, err := bigGammaShare.Curve().MarshalPoint(bigGammaShare)
	if err != nil {
		return nil, err
	}

	return &Broadcast3{
		BigGammaShare: bts,
	}, nil
}

func (x *Broadcast3) ValidateBasic() bool {
	return x != nil && x.BigGammaShare != nil
}

func (x *Broadcast3) GetProtocol() common.ProtocolType {
	return ProtocolName
}

func (x *Broadcast3) RoundNumber() int {
	return 3
}

func (x *Broadcast3) Reliable() bool {
	return true
}

func (x *Broadcast3) UnmarshalContent(crv curve.Curve) (curve.Point, error) {
	pt, err := crv.UnmarshalPoint(x.BigGammaShare)
	if err != nil {
		return nil, err
	}

	return pt, nil
}

func makeMessage3(
	DeltaD *paillier.Ciphertext, // DeltaD = Dᵢⱼ
	DeltaF *paillier.Ciphertext, // DeltaF = Fᵢⱼ
	DeltaProof *zkaffg.Proof,
	ChiD *paillier.Ciphertext, // DeltaD = D̂_{ij}
	ChiF *paillier.Ciphertext, // ChiF = F̂ᵢⱼ
	ChiProof *zkaffg.Proof,
	ProofLog *zklogstar.Proof) (*Message3, error) {

	deltaDBytes, err := DeltaD.MarshalBinary()
	if err != nil {
		return nil, err
	}
	deltaFBytes, err := DeltaF.MarshalBinary()
	if err != nil {
		return nil, err
	}

	deltaProofBytes, err := marshal.Encode(DeltaProof)
	if err != nil {
		return nil, err
	}
	chiDBytes, err := ChiD.MarshalBinary()
	if err != nil {
		return nil, err
	}
	chiFBytes, err := ChiF.MarshalBinary()
	if err != nil {
		return nil, err
	}

	chiProofBytes, err := marshal.Encode(ChiProof)
	if err != nil {
		return nil, err
	}
	proofLogBytes, err := marshal.Encode(ProofLog)
	if err != nil {
		return nil, err
	}

	return &Message3{
		DeltaD:     deltaDBytes,
		DeltaF:     deltaFBytes,
		DeltaProof: deltaProofBytes,
		ChiD:       chiDBytes,
		ChiF:       chiFBytes,
		ChiProof:   chiProofBytes,
		ProofLog:   proofLogBytes,
	}, nil
}

func (x *Message3) GetProtocol() common.ProtocolType {
	return ProtocolName
}

func (x *Message3) ValidateBasic() bool {
	return x != nil && len(x.DeltaD) > 0 && len(x.DeltaF) > 0 && len(x.DeltaProof) > 0 &&
		len(x.ChiD) > 0 && len(x.ChiF) > 0 && len(x.ChiProof) > 0 && len(x.ProofLog) > 0
}

func (x *Message3) Reliable() bool {
	return false
}

func (x *Message3) RoundNumber() int {
	return 3
}

type unmarsahledMessage3 struct {
	DeltaD     *paillier.Ciphertext // DeltaD = Dᵢⱼ
	DeltaF     *paillier.Ciphertext // DeltaF = Fᵢⱼ
	DeltaProof *zkaffg.Proof
	ChiD       *paillier.Ciphertext // DeltaD = D̂_{ij}
	ChiF       *paillier.Ciphertext // ChiF = F̂ᵢⱼ
	ChiProof   *zkaffg.Proof
	ProofLog   *zklogstar.Proof
}

func (x *Message3) UnmarshalContent(grp curve.Curve) (unmarsahledMessage3, error) {
	um3 := unmarsahledMessage3{}
	um3.DeltaD = &paillier.Ciphertext{}
	if err := um3.DeltaD.UnmarshalBinary(x.DeltaD); err != nil {
		return um3, err
	}

	um3.DeltaF = &paillier.Ciphertext{}
	if err := um3.DeltaF.UnmarshalBinary(x.DeltaF); err != nil {
		return um3, err
	}

	um3.DeltaProof = zkaffg.Empty(grp)
	if err := marshal.Decode(x.DeltaProof, um3.DeltaProof); err != nil {
		return um3, err
	}

	um3.ChiD = &paillier.Ciphertext{}
	if err := um3.ChiD.UnmarshalBinary(x.ChiD); err != nil {
		return um3, err
	}

	um3.ChiF = &paillier.Ciphertext{}
	if err := um3.ChiF.UnmarshalBinary(x.ChiF); err != nil {
		return um3, err
	}

	um3.ChiProof = zkaffg.Empty(grp)
	if err := marshal.Decode(x.ChiProof, um3.ChiProof); err != nil {
		return um3, err
	}

	um3.ProofLog = zklogstar.Empty(grp)
	if err := marshal.Decode(x.ProofLog, um3.ProofLog); err != nil {
		return um3, err
	}

	return um3, nil
}

// -- round 4 --

func makeMessage4(proofLog *zklogstar.Proof) (*Message4, error) {
	proofLogBytes, err := marshal.Encode(proofLog)
	if err != nil {
		return nil, err
	}

	return &Message4{
		ProofLog: proofLogBytes,
	}, nil
}

func (x *Message4) GetProtocol() common.ProtocolType {
	return ProtocolName
}

func (x *Message4) ValidateBasic() bool {
	return x != nil && len(x.ProofLog) > 0
}

func (x *Message4) Reliable() bool {
	return false
}

func (x *Message4) RoundNumber() int {
	return 4
}

func (x *Message4) UnmarshalContent(grp curve.Curve) (*zklogstar.Proof, error) {
	proofLog := zklogstar.Empty(grp)
	err := marshal.Decode(x.ProofLog, proofLog)
	return proofLog, err
}

func makeBroadcast4(DeltaShare curve.Scalar, BigDeltaShare curve.Point) (*Broadcast4, error) {
	deltaShareBytes, err := DeltaShare.Curve().MarshalScalar(DeltaShare)
	if err != nil {
		return nil, err
	}
	bigDeltaShareBytes, err := BigDeltaShare.Curve().MarshalPoint(BigDeltaShare)
	if err != nil {
		return nil, err
	}

	return &Broadcast4{
		DeltaShare:    deltaShareBytes,
		BigDeltaShare: bigDeltaShareBytes,
	}, nil
}

func (x *Broadcast4) ValidateBasic() bool {
	return x != nil && len(x.DeltaShare) > 0 && len(x.BigDeltaShare) > 0
}

func (x *Broadcast4) GetProtocol() common.ProtocolType {
	return ProtocolName
}

func (x *Broadcast4) RoundNumber() int {
	return 4
}

func (x *Broadcast4) Reliable() bool {
	return true
}

func (x *Broadcast4) UnmarshalContent(crv curve.Curve) (curve.Scalar, curve.Point, error) {
	deltaShare, err := crv.UnmarshalScalar(x.DeltaShare)
	if err != nil {
		return nil, nil, err
	}

	bigDeltaShare, err := crv.UnmarshalPoint(x.BigDeltaShare)
	return deltaShare, bigDeltaShare, err
}

// -- round 5 --

func makeBroadcast5(SigmaShare curve.Scalar) (*Broadcast5, error) {
	sigmaShareBytes, err := SigmaShare.Curve().MarshalScalar(SigmaShare)
	if err != nil {
		return nil, err
	}

	return &Broadcast5{
		SigmaShare: sigmaShareBytes,
	}, nil
}

func (x *Broadcast5) ValidateBasic() bool {
	return x != nil && len(x.SigmaShare) > 0
}

func (x *Broadcast5) GetProtocol() common.ProtocolType {
	return ProtocolName
}

func (x *Broadcast5) RoundNumber() int {
	return 5
}

func (x *Broadcast5) Reliable() bool {
	return true
}

func (x *Broadcast5) UnmarshalContent(crv curve.Curve) (curve.Scalar, error) {
	sigmaShare, err := crv.UnmarshalScalar(x.SigmaShare)
	return sigmaShare, err
}
