package mapper

import (
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

func TestMapResponseBuilder_Basic(t *testing.T) {
	cfg := &types.Config{
		BaseDomain: "example.com",
		LogTail: types.LogTailConfig{
			Enabled: true,
		},
	}

	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	builder := m.NewMapResponseBuilder(nodeID)

	// Test basic builder creation
	assert.NotNil(t, builder)
	assert.Equal(t, nodeID, builder.nodeID)
	assert.NotNil(t, builder.resp)
	assert.False(t, builder.resp.KeepAlive)
	assert.NotNil(t, builder.resp.ControlTime)
	assert.WithinDuration(t, time.Now(), *builder.resp.ControlTime, time.Second)
}

func TestMapResponseBuilder_WithCapabilityVersion(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)
	capVer := tailcfg.CapabilityVersion(42)

	builder := m.NewMapResponseBuilder(nodeID).
		WithCapabilityVersion(capVer)

	assert.Equal(t, capVer, builder.capVer)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_WithDomain(t *testing.T) {
	domain := "test.example.com"
	cfg := &types.Config{
		ServerURL:  "https://test.example.com",
		BaseDomain: domain,
	}

	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	builder := m.NewMapResponseBuilder(nodeID).
		WithDomain()

	assert.Equal(t, domain, builder.resp.Domain)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_WithCollectServicesDisabled(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	builder := m.NewMapResponseBuilder(nodeID).
		WithCollectServicesDisabled()

	value, isSet := builder.resp.CollectServices.Get()
	assert.True(t, isSet)
	assert.False(t, value)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_WithDebugConfig(t *testing.T) {
	tests := []struct {
		name           string
		logTailEnabled bool
		expected       *tailcfg.Debug
	}{
		{
			// Enabled sends no Debug, so the wire matches a server that never
			// touches client logging.
			name:           "LogTail enabled",
			logTailEnabled: true,
			expected:       nil,
		},
		{
			name:           "LogTail disabled",
			logTailEnabled: false,
			expected:       &tailcfg.Debug{DisableLogTail: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &types.Config{
				LogTail: types.LogTailConfig{
					Enabled: tt.logTailEnabled,
				},
			}
			mockState := &state.State{}
			m := &mapper{
				cfg:   cfg,
				state: mockState,
			}

			nodeID := types.NodeID(1)

			builder := m.NewMapResponseBuilder(nodeID).
				WithDebugConfig()

			assert.Equal(t, tt.expected, builder.resp.Debug)
			assert.False(t, builder.hasErrors())
		})
	}
}

func TestMapResponseBuilder_WithPeerChangedPatch(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)
	changes := []*tailcfg.PeerChange{
		{
			NodeID:     123,
			DERPRegion: 1,
		},
		{
			NodeID:     456,
			DERPRegion: 2,
		},
	}

	builder := m.NewMapResponseBuilder(nodeID).
		WithPeerChangedPatch(changes)

	assert.Equal(t, changes, builder.resp.PeersChangedPatch)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_WithPeersRemoved(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)
	removedID1 := types.NodeID(123)
	removedID2 := types.NodeID(456)

	builder := m.NewMapResponseBuilder(nodeID).
		WithPeersRemoved(removedID1, removedID2)

	expected := []tailcfg.NodeID{
		removedID1.NodeID(),
		removedID2.NodeID(),
	}
	assert.Equal(t, expected, builder.resp.PeersRemoved)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_ErrorHandling(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	// Simulate an error in the builder
	builder := m.NewMapResponseBuilder(nodeID)
	builder.addError(assert.AnError)

	// All subsequent calls should continue to work and accumulate errors
	result := builder.
		WithDomain().
		WithCollectServicesDisabled().
		WithDebugConfig()

	assert.True(t, result.hasErrors())
	assert.Len(t, result.errs, 1)
	assert.Equal(t, assert.AnError, result.errs[0])

	// Build should return the error
	data, err := result.Build()
	assert.Nil(t, data)
	assert.Error(t, err)
}

func TestMapResponseBuilder_ChainedCalls(t *testing.T) {
	domain := "chained.example.com"
	cfg := &types.Config{
		ServerURL:  "https://chained.example.com",
		BaseDomain: domain,
		LogTail: types.LogTailConfig{
			Enabled: false,
		},
	}

	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)
	capVer := tailcfg.CapabilityVersion(99)

	builder := m.NewMapResponseBuilder(nodeID).
		WithCapabilityVersion(capVer).
		WithDomain().
		WithCollectServicesDisabled().
		WithDebugConfig()

	// Verify all fields are set correctly
	assert.Equal(t, capVer, builder.capVer)
	assert.Equal(t, domain, builder.resp.Domain)
	value, isSet := builder.resp.CollectServices.Get()
	assert.True(t, isSet)
	assert.False(t, value)
	assert.NotNil(t, builder.resp.Debug)
	assert.True(t, builder.resp.Debug.DisableLogTail)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_MultipleWithPeersRemoved(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)
	removedID1 := types.NodeID(100)
	removedID2 := types.NodeID(200)

	// Test calling WithPeersRemoved multiple times
	builder := m.NewMapResponseBuilder(nodeID).
		WithPeersRemoved(removedID1).
		WithPeersRemoved(removedID2)

	// Second call should overwrite the first
	expected := []tailcfg.NodeID{removedID2.NodeID()}
	assert.Equal(t, expected, builder.resp.PeersRemoved)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_EmptyPeerChangedPatch(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	builder := m.NewMapResponseBuilder(nodeID).
		WithPeerChangedPatch([]*tailcfg.PeerChange{})

	assert.Empty(t, builder.resp.PeersChangedPatch)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_NilPeerChangedPatch(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	builder := m.NewMapResponseBuilder(nodeID).
		WithPeerChangedPatch(nil)

	assert.Nil(t, builder.resp.PeersChangedPatch)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_MultipleErrors(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	// Create a builder and add multiple errors
	builder := m.NewMapResponseBuilder(nodeID)
	builder.addError(assert.AnError)
	builder.addError(assert.AnError)
	builder.addError(nil) // This should be ignored

	// All subsequent calls should continue to work
	result := builder.
		WithDomain().
		WithCollectServicesDisabled()

	assert.True(t, result.hasErrors())
	assert.Len(t, result.errs, 2) // nil error should be ignored

	// Build should return a multierr
	data, err := result.Build()
	require.Nil(t, data)
	require.Error(t, err)

	// The error should contain information about multiple errors
	assert.Contains(t, err.Error(), "multiple errors")
}

func TestAsMullvadExitNode(t *testing.T) {
	exitRoutes := []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()}
	tokyo := tailcfg.Location{Country: "Japan", CountryCode: "JP", City: "Tokyo", CityCode: "TYO"}
	locs := map[string]tailcfg.Location{"mullvad-jp": tokyo}

	peer := func(name string, approved []netip.Prefix) (*types.Node, *tailcfg.Node) {
		n := &types.Node{
			GivenName:      name,
			Hostinfo:       &tailcfg.Hostinfo{Hostname: name, RoutableIPs: exitRoutes},
			ApprovedRoutes: approved,
		}

		return n, &tailcfg.Node{Name: name + ".example.com.", Hostinfo: n.View().Hostinfo()}
	}

	n, tn := peer("mullvad-jp", exitRoutes)
	asMullvadExitNode(tn, n.View(), locs)
	assert.Equal(t, "mullvad-jp.mullvad.ts.net.", tn.Name)
	assert.Equal(t, tokyo, *tn.Hostinfo.Location().AsStruct())
	assert.Equal(t, "mullvad-jp", tn.Hostinfo.Hostname())
	assert.Nil(t, n.Hostinfo.Location, "the stored Hostinfo must stay untouched")

	// Not an exit node until the routes are approved.
	n, tn = peer("mullvad-jp", nil)
	asMullvadExitNode(tn, n.View(), locs)
	assert.Equal(t, "mullvad-jp.example.com.", tn.Name)
	assert.False(t, tn.Hostinfo.Location().Valid())

	// Not listed.
	n, tn = peer("home-exit", exitRoutes)
	asMullvadExitNode(tn, n.View(), locs)
	assert.Equal(t, "home-exit.example.com.", tn.Name)
	assert.False(t, tn.Hostinfo.Location().Valid())
}
