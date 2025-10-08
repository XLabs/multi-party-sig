package zkfac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xlabs/multi-party-sig/internal/marshal"
	"github.com/xlabs/multi-party-sig/pkg/hash"
	"github.com/xlabs/multi-party-sig/pkg/paillier"
	"github.com/xlabs/multi-party-sig/pkg/pool"
)

func TestFac(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	aux, _ := paillier.NewSecretKey(pl).GeneratePedersen()
	sk := paillier.NewSecretKey(pl)

	public := Public{
		N:   sk.Modulus().Modulus,
		Aux: aux,
	}

	proof := NewProof(Private{
		P: sk.P(),
		Q: sk.Q(),
	}, hash.New(), public)
	assert.True(t, proof.Verify(public, hash.New()))

	out, err := marshal.Encode(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := &Proof{}
	require.NoError(t, marshal.Decode(out, proof2), "failed to unmarshal proof")
	out2, err := marshal.Encode(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := &Proof{}
	require.NoError(t, marshal.Decode(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(public, hash.New()))
}
