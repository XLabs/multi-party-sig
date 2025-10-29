package config_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xlabs/multi-party-sig/internal/test"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/pool"
	"github.com/xlabs/multi-party-sig/protocols/cmp/config"
)

func TestMarshal(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N, T := 5, 3
	group := curve.Secp256k1{}
	configs, partyIDs := test.GenerateConfig(group, N, T, rand.Reader, pl)

	originalConfig := configs[partyIDs[0]]

	data, err := originalConfig.MarshalBinary()
	require.NoError(t, err, "failed to marshal config")

	unmarshaledConfig := config.EmptyConfig(group)
	err = unmarshaledConfig.UnmarshalBinary(data)
	require.NoError(t, err, "failed to unmarshal config")

	assertConfig(t, originalConfig, unmarshaledConfig)
}

func assertConfig(t *testing.T, expected, actual *config.Config) {
	assert.Equal(t, expected.ID, actual.ID, "ID mismatch")
	assert.Equal(t, expected.Threshold, actual.Threshold, "Threshold mismatch")
	assert.True(t, expected.ECDSA.Equal(actual.ECDSA), "ECDSA secret key mismatch")
	assert.True(t, expected.ElGamal.Equal(actual.ElGamal), "ElGamal secret key mismatch")

	// asserting Pallier keys
	assert.True(t, expected.Paillier.P().Eq(actual.Paillier.P()) == 1, "Paillier P mismatch")
	assert.True(t, expected.Paillier.Q().Eq(actual.Paillier.Q()) == 1, "Paillier Q mismatch")
	assert.True(t, expected.Paillier.N().Nat().Eq(actual.Paillier.N().Nat()) == 1, "Paillier N mismatch")

	assert.Equal(t, expected.RID, actual.RID, "RID mismatch")
	assert.Equal(t, expected.ChainKey, actual.ChainKey, "ChainKey mismatch")

	assertPublic(t, expected, actual)
}

func assertPublic(t *testing.T, expected, actual *config.Config) {
	require.Equal(t, len(expected.Public), len(actual.Public), "Public map length mismatch")

	for id, originalPublic := range expected.Public {
		unmarshaledPublic, ok := actual.Public[id]
		require.True(t, ok, "missing party in unmarshaled public map: %s", id)

		assert.True(t, originalPublic.ECDSA.Equal(unmarshaledPublic.ECDSA), "Public.ECDSA key mismatch for party %s", id)
		assert.True(t, originalPublic.ElGamal.Equal(unmarshaledPublic.ElGamal), "Public.ElGamal key mismatch for party %s", id)
		assert.True(t, originalPublic.Paillier.Equal(unmarshaledPublic.Paillier), "Public.Paillier key mismatch for party %s", id)
		assert.True(t, originalPublic.Pedersen.N().Nat().Eq(unmarshaledPublic.Pedersen.N().Nat()) == 1, "Public.Pedersen N mismatch for party %s", id)
		assert.True(t, originalPublic.Pedersen.S().Eq(unmarshaledPublic.Pedersen.S()) == 1, "Public.Pedersen S mismatch for party %s", id)
		assert.True(t, originalPublic.Pedersen.T().Eq(unmarshaledPublic.Pedersen.T()) == 1, "Public.Pedersen T mismatch for party %s", id)
	}
}
