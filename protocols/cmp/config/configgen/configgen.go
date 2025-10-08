package configgen

import (
	"io"
	"runtime"

	"github.com/xlabs/multi-party-sig/internal/test"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/pool"
	"github.com/xlabs/multi-party-sig/protocols/cmp/config"
)

// This is a wrapper function to export the GenerateConfigForParties function from internal/test/cmp_config.go
func GenerateCmpTestConfig(group curve.Curve, partyIDs party.IDSlice, T int, source io.Reader) map[party.ID]*config.Config {
	p := pool.NewPool(runtime.NumCPU())
	defer p.TearDown()

	return test.GenerateConfigForParties(group, partyIDs, T, source, p)
}
