package frost

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xlabs/multi-party-sig/internal/test"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/protocol"
	"github.com/xlabs/multi-party-sig/pkg/taproot"
	"github.com/xlabs/multi-party-sig/protocols/frost/sign"
	common "github.com/xlabs/tss-common"
)

// dummy tracking ID for tests
var testTrackid = &common.TrackingID{
	Digest:        []byte{1, 2, 3, 4},
	PartiesState:  nil,
	AuxiliaryData: nil,
	Protocol:      uint32(common.ProtocolFROSTSign.ToInt()),
}

func do(t *testing.T, id party.ID, ids []party.ID, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup) {
	var cnfg *Config
	defer wg.Done()
	for i := 0; i < 10; i++ {
		h, err := protocol.NewMultiHandler(Keygen(curve.Secp256k1{}, id, ids, threshold), testTrackid.ToByteString())
		require.NoError(t, err)
		test.HandlerLoop(id, h, n)
		r, err := h.Result()
		require.NoError(t, err)
		require.IsType(t, &Config{}, r)
		c0 := r.(*Config)
		if sign.PublicKeyValidForContract(c0.PublicKey) {
			fmt.Println("found valid public key. attempt #", i+1)
			cnfg = c0
			break
		}
		if i == 50 {
			t.Fatalf("public key is not valid for contract after 50 attempts, something is wrong.")
		}
	}

	c0 := cnfg
	h, err := protocol.NewMultiHandler(Refresh(c0, ids), testTrackid.ToByteString())
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c := r.(*Config)
	require.True(t, c0.PublicKey.Equal(c.PublicKey))

	h, err = protocol.NewMultiHandler(KeygenTaproot(id, ids, threshold), testTrackid.ToByteString())
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &TaprootConfig{}, r)

	c0Taproot := r.(*TaprootConfig)

	h, err = protocol.NewMultiHandler(RefreshTaproot(c0Taproot, ids), testTrackid.ToByteString())
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &TaprootConfig{}, r)

	cTaproot := r.(*TaprootConfig)
	require.True(t, bytes.Equal(c0Taproot.PublicKey, cTaproot.PublicKey))

	h, err = protocol.NewMultiHandler(Sign(c, ids, message), testTrackid.ToByteString())
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, Signature{}, signResult)
	signature := signResult.(Signature)
	assert.NoError(t, signature.Verify(c.PublicKey, message))

	h, err = protocol.NewMultiHandler(SignTaproot(cTaproot, ids, message), testTrackid.ToByteString())
	require.NoError(t, err)

	test.HandlerLoop(c.ID, h, n)

	signResult, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, taproot.Signature{}, signResult)
	taprootSignature := signResult.(taproot.Signature)
	assert.True(t, cTaproot.PublicKey.Verify(taprootSignature, message))
}

func TestFrost(t *testing.T) {
	N := 5
	T := N - 1
	message := []byte("hello")

	partyIDs := test.PartyIDs(N)
	fmt.Println(partyIDs)

	n := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	wg.Add(N)
	for _, id := range partyIDs {
		go do(t, id, partyIDs, T, message, n, &wg)
	}
	wg.Wait()
}
