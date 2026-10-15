package mapper

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// mullvadDirectFor builds a two-city node.mullvad_direct (Tokyo, Osaka) for
// the given viewers, through the parser the config uses.
func mullvadDirectFor(t *testing.T, cfg *types.Config, viewers ...key.NodePublic) *types.MullvadDirect {
	t.Helper()

	relay := func(host, city, ip string) map[string]any {
		k := key.NewNode().Public().Raw32()

		return map[string]any{
			"hostname": host, "country_name": "Japan", "city_name": city, "active": true,
			"owned": true, "type": "wireguard", "ipv4_addr_in": ip,
			"pubkey": base64.StdEncoding.EncodeToString(k[:]),
		}
	}

	relays, err := json.Marshal([]any{
		relay("jp-tyo-wg-001", "Tokyo", "192.0.2.1"),
		relay("jp-osa-wg-001", "Osaka", "192.0.2.2"),
	})
	require.NoError(t, err)

	raw := types.MullvadDirectConfig{DNS: "10.64.0.1", DefaultCity: "jp-tyo"}
	for i, k := range viewers {
		raw.Devices = append(raw.Devices, types.MullvadDeviceConfig{
			Name:    fmt.Sprintf("dev%d", i),
			NodeKey: k.String(),
			IPv4:    fmt.Sprintf("10.124.0.%d/32", i+1),
			IPv6:    fmt.Sprintf("fc00:bbbb:bbbb:bb01::%x/128", i+1),
		})
	}

	md, err := raw.Parse(relays, cfg.PrefixV4, cfg.PrefixV6, types.IPAllocationStrategySequential)
	require.NoError(t, err)

	return md
}

// mullvadIDs returns the synthetic Mullvad IDs among nodes.
func mullvadIDs(nodes []*tailcfg.Node) []tailcfg.NodeID {
	var ids []tailcfg.NodeID

	for _, n := range nodes {
		if types.IsMullvadDirectID(n.ID) {
			ids = append(ids, n.ID)
		}
	}

	return ids
}

// mullvadRemoved returns the synthetic Mullvad IDs that frames remove.
func mullvadRemoved(frames []*tailcfg.MapResponse) []tailcfg.NodeID {
	var ids []tailcfg.NodeID

	for _, f := range frames {
		for _, id := range f.PeersRemoved {
			if types.IsMullvadDirectID(id) {
				ids = append(ids, id)
			}
		}
	}

	return ids
}

func sortedByID(nodes []*tailcfg.Node) bool {
	return slices.IsSortedFunc(nodes, func(a, b *tailcfg.Node) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}

		return 0
	})
}

func taggedProfiles(profiles []tailcfg.UserProfile) int {
	n := 0

	for _, p := range profiles {
		if p.ID == tailcfg.UserID(types.TaggedDevicesUserID) {
			n++
		}
	}

	return n
}

func drainResponses(ch <-chan *tailcfg.MapResponse) []*tailcfg.MapResponse {
	var out []*tailcfg.MapResponse

	for {
		select {
		case r := <-ch:
			out = append(out, r)
		default:
			return out
		}
	}
}

// collectResponses reads from ch until it has been quiet for quiet; the real
// batcher sends asynchronously.
func collectResponses(ch <-chan *tailcfg.MapResponse, quiet time.Duration) []*tailcfg.MapResponse {
	var out []*tailcfg.MapResponse

	for {
		select {
		case r := <-ch:
			out = append(out, r)
		case <-time.After(quiet):
			return out
		}
	}
}

// applyLikeClient applies responses to a peer set the way the client does
// (tailscale.com/control/controlclient): a non-empty Peers replaces the set;
// otherwise PeersRemoved deletes and PeersChanged upserts.
func applyLikeClient(peers map[tailcfg.NodeID]*tailcfg.Node, resps ...*tailcfg.MapResponse) {
	for _, r := range resps {
		if len(r.Peers) > 0 {
			clear(peers)

			for _, p := range r.Peers {
				peers[p.ID] = p
			}

			continue
		}

		for _, id := range r.PeersRemoved {
			delete(peers, id)
		}

		for _, p := range r.PeersChanged {
			peers[p.ID] = p
		}
	}
}

// runTick runs one batch tick on b and waits until the worker has delivered
// or requeued nc's bundle.
func runTick(t *testing.T, b *Batcher, nc *multiChannelNodeConn) {
	t.Helper()

	b.processBatchedChanges()
	require.Eventually(t, func() bool { return !nc.inFlight.Load() }, updateTimeout, time.Millisecond)
}

func TestMullvadDirectPeersFields(t *testing.T) {
	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{PrefixV4: &p4, PrefixV6: &p6}

	k := key.NewNode().Public()
	cfg.Node.MullvadDirect = mullvadDirectFor(t, cfg, k)
	md := cfg.Node.MullvadDirect
	dev := md.Devices[k]

	uid := uint(1)
	viewer := (&types.Node{ID: 1, NodeKey: k, UserID: &uid}).View()

	peers := mullvadDirectPeers(viewer, cfg)
	require.Len(t, peers, 2)
	assert.True(t, sortedByID(peers))
	assert.Equal(t, mullvadIDs(peers), mullvadDirectIDs(viewer, cfg))

	for i, p := range peers {
		s := md.Servers[i]

		assert.Equal(t, s.ID, p.ID)
		assert.True(t, types.IsMullvadDirectID(p.ID))
		assert.Equal(t, s.StableID, p.StableID)
		assert.Equal(t, s.Name, p.Name)
		assert.True(t, strings.HasSuffix(p.Name, ".mullvad.ts.net."))
		assert.Equal(t, tailcfg.UserID(types.TaggedDevicesUserID), p.User, "never the viewer's own user")
		assert.NotEqual(t, viewer.TailscaleUserID(), p.User)
		assert.Equal(t, []string{"tag:mullvad-direct"}, p.Tags)
		assert.Equal(t, s.Key, p.Key)

		assert.Equal(t, []netip.Prefix{s.Addr4, s.Addr6}, p.Addresses)
		assert.Subset(t, p.AllowedIPs, p.Addresses)
		assert.True(t, tsaddr.ContainsExitRoutes(views.SliceOf(p.AllowedIPs)))
		assert.Equal(t, []netip.AddrPort{s.Endpoint}, p.Endpoints)

		require.True(t, p.Hostinfo.Valid())
		assert.Equal(t, s.Hostname, p.Hostinfo.Hostname())
		require.True(t, p.Hostinfo.Location().Valid())
		assert.Equal(t, s.Location, *p.Hostinfo.Location().AsStruct())

		assert.Equal(t, tailcfg.NodeCapMap{nodecap.SuggestExitNode: nil}, p.CapMap)
		require.NotNil(t, p.Online)
		assert.True(t, *p.Online)
		assert.True(t, p.MachineAuthorized)
		assert.True(t, p.IsWireGuardOnly)
		assert.True(t, p.IsJailed)

		require.NotNil(t, p.SelfNodeV4MasqAddrForThisPeer)
		require.NotNil(t, p.SelfNodeV6MasqAddrForThisPeer)
		assert.Equal(t, dev.IPv4, *p.SelfNodeV4MasqAddrForThisPeer)
		assert.Equal(t, dev.IPv6, *p.SelfNodeV6MasqAddrForThisPeer)
		assert.Equal(t, []*dnstype.Resolver{{Addr: "10.64.0.1"}}, p.ExitNodeDNSResolvers)

		assert.Zero(t, p.Cap, "Cap must stay 0: from 26 up, clients expect a peerapi DNS proxy")
		assert.True(t, p.DiscoKey.IsZero())
		assert.Zero(t, p.HomeDERP)
		assert.True(t, p.KeyExpiry.IsZero())
		assert.False(t, p.Expired)
		assert.Nil(t, p.LastSeen)
	}

	t.Run("fresh-nodes-per-call", func(t *testing.T) {
		again := mullvadDirectPeers(viewer, cfg)
		*again[0].SelfNodeV4MasqAddrForThisPeer = netip.MustParseAddr("10.9.9.9")
		again[0].Tags[0] = "tag:changed"

		assert.Equal(t, dev.IPv4, *peers[0].SelfNodeV4MasqAddrForThisPeer)
		assert.Equal(t, "tag:mullvad-direct", peers[0].Tags[0])
		assert.Equal(t, md.Servers[0].Location, *mullvadDirectPeers(viewer, cfg)[0].Hostinfo.Location().AsStruct())
	})

	t.Run("fails-closed", func(t *testing.T) {
		other := (&types.Node{ID: 2, NodeKey: key.NewNode().Public(), UserID: &uid}).View()
		tagged := (&types.Node{ID: 3, NodeKey: k, UserID: &uid, Tags: []string{"tag:x"}}).View()

		for name, tc := range map[string]struct {
			viewer types.NodeView
			cfg    *types.Config
		}{
			"unlisted viewer": {other, cfg},
			"tagged viewer":   {tagged, cfg},
			"invalid view":    {types.NodeView{}, cfg},
			"nil config":      {viewer, nil},
			"no block":        {viewer, &types.Config{}},
		} {
			assert.Nil(t, mullvadDirectPeers(tc.viewer, tc.cfg), name)
			assert.Nil(t, mullvadDirectIDs(tc.viewer, tc.cfg), name)
		}
	})
}

// TestMullvadDirectSurvivesPolicyChange covers the PolicyChange path, which
// derives removals from the real peers. It must not send the synthetic peers
// as removed while the viewer still gets them, or a phone loses its
// selected exit on every policy reload; and it must remove them once the
// viewer no longer does. It runs the real per-node tracking
// (multiChannelNodeConn); the mock connection has its own copy of the diff.
func TestMullvadDirectSurvivesPolicyChange(t *testing.T) {
	for _, nodes := range []int{1, 3} {
		t.Run(fmt.Sprintf("nodes=%d", nodes), func(t *testing.T) {
			td, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, nodes, normalBufferSize)
			defer cleanup()

			viewer := td.Nodes[0].n
			td.Config.Node.MullvadDirect = mullvadDirectFor(t, td.Config, viewer.NodeKey)

			want := mullvadIDs(mullvadDirectPeers(viewer.View(), td.Config))
			require.Len(t, want, 2)

			m := td.Batcher.mapper
			ch := make(chan *tailcfg.MapResponse, normalBufferSize)
			nc := newMultiChannelNodeConn(viewer.ID, m)
			nc.addConnection(makeConnectionEntry("c1", ch))

			client := make(map[tailcfg.NodeID]*tailcfg.Node)

			require.NoError(t, handleNodeChange(nc, m, change.FullSelf(viewer.ID)))

			frames := drainResponses(ch)
			require.NotEmpty(t, frames)

			full := frames[len(frames)-1]
			assert.ElementsMatch(t, want, mullvadIDs(full.Peers))
			assert.Len(t, full.Peers, nodes-1+len(want))
			assert.True(t, sortedByID(full.Peers))
			assert.Equal(t, 1, taggedProfiles(full.UserProfiles), "the owner's profile is sent once")
			applyLikeClient(client, frames...)

			for range 2 {
				require.NoError(t, handleNodeChange(nc, m, change.PolicyChange()))

				frames = drainResponses(ch)
				assert.Empty(t, mullvadRemoved(frames), "policy change sent synthetic peers as removed")

				for _, f := range frames {
					assert.Empty(t, mullvadIDs(f.PeersChanged))
				}

				applyLikeClient(client, frames...)

				for _, id := range want {
					assert.Contains(t, client, id, "client lost synthetic peer %d", id)
				}
			}

			require.NoError(t, handleNodeChange(nc, m, change.FullUpdate()))

			frames = drainResponses(ch)
			require.Len(t, frames, 1, "no removal frame")
			assert.ElementsMatch(t, want, mullvadIDs(frames[0].Peers))
			applyLikeClient(client, frames...)

			// The viewer stops qualifying (here: no longer listed). The
			// next policy change removes the peers.
			td.Config.Node.MullvadDirect = mullvadDirectFor(t, td.Config, key.NewNode().Public())
			require.NoError(t, handleNodeChange(nc, m, change.PolicyChange()))

			frames = drainResponses(ch)
			assert.ElementsMatch(t, want, mullvadRemoved(frames))
			applyLikeClient(client, frames...)

			for _, id := range want {
				assert.NotContains(t, client, id)
			}
		})
	}
}

// TestMullvadDirectProductionStreams drives the production batcher: initial
// map, a policy change through the worker, a second concurrent stream, a
// reconnect and a full update. Each channel is its own client session.
func TestMullvadDirectProductionStreams(t *testing.T) {
	td, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 3, normalBufferSize)
	defer cleanup()

	viewer := td.Nodes[0].n
	td.Config.Node.MullvadDirect = mullvadDirectFor(t, td.Config, viewer.NodeKey)

	want := mullvadIDs(mullvadDirectPeers(viewer.View(), td.Config))
	require.Len(t, want, 2)

	b := td.Batcher
	capVer := tailcfg.CapabilityVersion(100)
	quiet := 300 * time.Millisecond

	ch1 := make(chan *tailcfg.MapResponse, normalBufferSize)
	require.NoError(t, b.AddNode(viewer.ID, ch1, capVer, nil))

	c1 := map[tailcfg.NodeID]*tailcfg.Node{}
	f1 := collectResponses(ch1, quiet)
	require.NotEmpty(t, f1)
	require.NotNil(t, f1[0].Node, "first frame carries self")
	assert.ElementsMatch(t, want, mullvadIDs(f1[0].Peers))
	applyLikeClient(c1, f1...)

	b.AddWork(change.PolicyChange())

	f1 = collectResponses(ch1, quiet)
	assert.Empty(t, mullvadRemoved(f1))
	applyLikeClient(c1, f1...)

	for _, id := range want {
		assert.Contains(t, c1, id)
	}

	// A second concurrent stream.
	ch2 := make(chan *tailcfg.MapResponse, normalBufferSize)
	require.NoError(t, b.AddNode(viewer.ID, ch2, capVer, nil))

	c2 := map[tailcfg.NodeID]*tailcfg.Node{}
	f2 := collectResponses(ch2, quiet)
	require.NotEmpty(t, f2)
	assert.ElementsMatch(t, want, mullvadIDs(f2[0].Peers))
	applyLikeClient(c2, f2...)

	f1 = collectResponses(ch1, quiet/3)
	assert.Empty(t, mullvadRemoved(f1))
	applyLikeClient(c1, f1...)

	// A reconnect: ch1 goes, ch3 comes.
	b.RemoveNode(viewer.ID, ch1)

	ch3 := make(chan *tailcfg.MapResponse, normalBufferSize)
	require.NoError(t, b.AddNode(viewer.ID, ch3, capVer, nil))

	c3 := map[tailcfg.NodeID]*tailcfg.Node{}
	f3 := collectResponses(ch3, quiet)
	require.NotEmpty(t, f3)
	assert.ElementsMatch(t, want, mullvadIDs(f3[0].Peers))
	assert.Empty(t, mullvadRemoved(f3))
	applyLikeClient(c3, f3...)

	b.AddWork(change.PolicyChange())
	b.AddWork(change.FullUpdate())

	f2 = collectResponses(ch2, quiet)
	f3 = collectResponses(ch3, quiet/3)
	assert.Empty(t, mullvadRemoved(f2))
	assert.Empty(t, mullvadRemoved(f3))
	applyLikeClient(c2, f2...)
	applyLikeClient(c3, f3...)

	for _, id := range want {
		assert.Contains(t, c2, id)
		assert.Contains(t, c3, id)
	}

	// Every full Peers list carries the synthetic peers exactly once.
	for _, f := range slices.Concat(f2, f3) {
		if f.Peers != nil {
			assert.ElementsMatch(t, want, mullvadIDs(f.Peers))
			assert.True(t, sortedByID(f.Peers))
		}
	}
}

// TestMullvadDirectTaggedViewerLosesPeers: a listed device tagged while it
// streams no longer qualifies, and loses the synthetic peers without waiting
// for a full map.
func TestMullvadDirectTaggedViewerLosesPeers(t *testing.T) {
	td, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 2, normalBufferSize)
	defer cleanup()

	_, err := td.State.SetPolicy([]byte(`{
		"tagOwners": {"tag:x": ["testuser-0@"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	viewer := td.Nodes[0].n
	td.Config.Node.MullvadDirect = mullvadDirectFor(t, td.Config, viewer.NodeKey)
	want := mullvadIDs(mullvadDirectPeers(viewer.View(), td.Config))

	m := td.Batcher.mapper
	ch := make(chan *tailcfg.MapResponse, normalBufferSize)
	nc := newMultiChannelNodeConn(viewer.ID, m)
	nc.addConnection(makeConnectionEntry("c1", ch))

	client := map[tailcfg.NodeID]*tailcfg.Node{}

	require.NoError(t, handleNodeChange(nc, m, change.FullSelf(viewer.ID)))
	applyLikeClient(client, drainResponses(ch)...)

	for _, id := range want {
		require.Contains(t, client, id)
	}

	nv, c, err := td.State.SetNodeTags(viewer.ID, []string{"tag:x"})
	require.NoError(t, err)
	require.True(t, nv.IsTagged())
	require.Empty(t, mullvadDirectPeers(nv, td.Config))

	require.NoError(t, handleNodeChange(nc, m, c))
	applyLikeClient(client, drainResponses(ch)...)

	for _, id := range want {
		assert.NotContains(t, client, id, "the tag change itself removes the peers")
	}

	// And nothing brings them back.
	require.NoError(t, handleNodeChange(nc, m, change.PolicyChange()))
	applyLikeClient(client, drainResponses(ch)...)

	for _, id := range want {
		assert.NotContains(t, client, id)
	}
}

// TestMullvadDirectTaggedProfileOnce: when the viewer also sees a real
// tagged node, the tagged-devices profile is still sent once.
func TestMullvadDirectTaggedProfileOnce(t *testing.T) {
	td, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 2, normalBufferSize)
	defer cleanup()

	_, err := td.State.SetPolicy([]byte(`{
		"tagOwners": {"tag:x": ["testuser-0@"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	_, _, err = td.State.SetNodeTags(td.Nodes[1].n.ID, []string{"tag:x"})
	require.NoError(t, err)

	viewer := td.Nodes[0].n
	td.Config.Node.MullvadDirect = mullvadDirectFor(t, td.Config, viewer.NodeKey)

	resps, err := generateMapResponse(newMockNodeConnection(viewer.ID), td.Batcher.mapper, change.FullSelf(viewer.ID))
	require.NoError(t, err)

	full := resps[len(resps)-1]
	require.Len(t, mullvadIDs(full.Peers), 2)
	require.Len(t, full.Peers, 3, "the tagged real peer is visible too")
	assert.Equal(t, 1, taggedProfiles(full.UserProfiles))
}

// TestMullvadDirectAbsentLeavesMapsUnchanged: without node.mullvad_direct,
// every response is what it was before the feature.
func TestMullvadDirectAbsentLeavesMapsUnchanged(t *testing.T) {
	td, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 2, 2, normalBufferSize)
	defer cleanup()

	require.Nil(t, td.Config.Node.MullvadDirect)

	m := td.Batcher.mapper
	id := td.Nodes[0].n.ID
	peers := m.state.ListPeers(id)

	want, err := m.NewMapResponseBuilder(id).
		WithCapabilityVersion(tailcfg.CurrentCapabilityVersion).
		buildTailPeers(peers)
	require.NoError(t, err)

	b := m.NewMapResponseBuilder(id).
		WithCapabilityVersion(tailcfg.CurrentCapabilityVersion).
		WithUserProfiles(peers)
	wantProfiles := slices.Clone(b.resp.UserProfiles)
	got := b.WithPeers(peers).resp

	if diff := cmp.Diff(want, got.Peers); diff != "" {
		t.Errorf("WithPeers differs from buildTailPeers (-want +got):\n%s", diff)
	}

	assert.Equal(t, wantProfiles, got.UserProfiles)

	var realIDs []tailcfg.NodeID
	for _, p := range peers.All() {
		realIDs = append(realIDs, p.ID().NodeID())
	}

	peerID := td.Nodes[1].n.ID
	changes := []change.Change{
		change.FullSelf(id), change.FullUpdate(), change.PolicyChange(),
		change.NodeOnline(peerID), change.NodeAdded(peerID), change.SelfUpdate(id),
		change.DERPMap(), change.DNSConfig(),
	}

	for _, c := range changes {
		resps, err := generateMapResponse(newMockNodeConnection(id), m, c)
		require.NoError(t, err, c.Reason)

		for _, r := range resps {
			assert.Empty(t, mullvadIDs(r.Peers), c.Reason)
			assert.Empty(t, mullvadIDs(r.PeersChanged), c.Reason)
			assert.Empty(t, r.PeersRemoved, c.Reason)
			assert.Zero(t, taggedProfiles(r.UserProfiles), c.Reason)

			if r.Peers != nil {
				var ids []tailcfg.NodeID
				for _, p := range r.Peers {
					ids = append(ids, p.ID)
				}

				assert.ElementsMatch(t, realIDs, ids, c.Reason)
			}
		}
	}
}

// TestMullvadDirectOnlyForListedViewers: only a listed node key gets the
// synthetic peers, only in full lists; a listed key that matches no node
// changes nothing.
func TestMullvadDirectOnlyForListedViewers(t *testing.T) {
	td, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 2, 2, normalBufferSize)
	defer cleanup()

	listed := td.Nodes[0].n
	td.Config.Node.MullvadDirect = mullvadDirectFor(t, td.Config, listed.NodeKey, key.NewNode().Public())

	m := td.Batcher.mapper

	for i := range td.Nodes {
		id := td.Nodes[i].n.ID

		want := 0
		if id == listed.ID {
			want = 2
		}

		for _, c := range []change.Change{change.FullSelf(id), change.FullUpdate(), change.PolicyChange()} {
			resps, err := generateMapResponse(newMockNodeConnection(id), m, c)
			require.NoError(t, err, c.Reason)

			for _, r := range resps {
				assert.Empty(t, mullvadIDs(r.PeersChanged), c.Reason)

				if r.Peers != nil {
					assert.Len(t, mullvadIDs(r.Peers), want, "node %d, %s", id, c.Reason)
					assert.Equal(t, min(want, 1), taggedProfiles(r.UserProfiles), "node %d, %s", id, c.Reason)
					assert.True(t, sortedByID(r.Peers))
				}
			}
		}
	}
}

// TestMullvadDirectPartialDelivery covers a full peer list that reaches only
// some of the viewer's streams, as in a reconnect overlap: send() records
// what it delivered as partial additions (partialPeers), reports
// backpressure, and confirms nothing as sent (lastSentPeers). Every peer
// diff ranges both. While the viewer qualifies, the retried full must not
// remove the synthetic peers; once it stops, the retry must, though only
// partialPeers knows the client has them. The test drives the connection
// directly, in the worker's order, plus one policy diff the worker cannot
// reach in this state.
func TestMullvadDirectPartialDelivery(t *testing.T) {
	td, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 2, normalBufferSize)
	defer cleanup()

	viewer := td.Nodes[0].n
	td.Config.Node.MullvadDirect = mullvadDirectFor(t, td.Config, viewer.NodeKey)

	want := mullvadIDs(mullvadDirectPeers(viewer.View(), td.Config))
	require.Len(t, want, 2)

	// The newest stream's client has not read yet; its queue is full. Only
	// the newest stream is kept blocked: send() retires blocked siblings
	// once the newest accepts.
	m := td.Batcher.mapper
	older := make(chan *tailcfg.MapResponse, normalBufferSize)

	newest := make(chan *tailcfg.MapResponse, 1)
	newest <- testMapResponse()

	nc := newMultiChannelNodeConn(viewer.ID, m)
	nc.addConnection(makeConnectionEntry("older", older))
	nc.addConnection(makeConnectionEntry("newest", newest))

	// partialOnly reports whether nc knows id only as a partial addition.
	partialOnly := func(id tailcfg.NodeID) bool {
		_, partial := nc.partialPeers.Load(id)
		_, sent := nc.lastSentPeers.Load(id)

		return partial && !sent
	}

	client := map[tailcfg.NodeID]*tailcfg.Node{}

	// The full reaches the older stream only.
	require.ErrorIs(t, handleNodeChange(nc, m, change.FullUpdate()), errConnectionBackpressure)

	frames := drainResponses(older)
	require.Len(t, frames, 1)
	require.ElementsMatch(t, want, mullvadIDs(frames[0].Peers))
	applyLikeClient(client, frames...)

	for _, id := range want {
		require.True(t, partialOnly(id), "synthetic peer %d not recorded as a partial addition", id)
	}

	// The worker requeues the full, which absorbs any change queued behind
	// it, and retries it while the viewer still qualifies. The newest stream
	// still blocks, well short of the stall eviction, so the retry is partial
	// too. Its diff finds the synthetic peers in partialPeers alone, and must
	// not remove them.
	require.ErrorIs(t, handleNodeChange(nc, m, change.FullUpdate()), errConnectionBackpressure)

	frames = drainResponses(older)
	require.Len(t, frames, 1, "the retried full, with no removal frame")
	assert.ElementsMatch(t, want, mullvadIDs(frames[0].Peers))
	assert.Empty(t, mullvadRemoved(frames), "the retry removed partially delivered synthetic peers")
	applyLikeClient(client, frames...)

	for _, id := range want {
		require.True(t, partialOnly(id), "synthetic peer %d left partialPeers", id)
	}

	// The blocked stream goes away, so no send below waits on it.
	require.True(t, nc.removeConnectionByChannel(newest))

	// The batcher folds a policy change into the requeued full, so this
	// step cannot happen through it; it checks the policy diff directly,
	// which must count the synthetic peers as present though only
	// partialPeers has them.
	require.NoError(t, handleNodeChange(nc, m, change.PolicyChange()))

	frames = drainResponses(older)
	require.NotEmpty(t, frames)
	assert.Empty(t, mullvadRemoved(frames), "policy change removed partially delivered synthetic peers")

	for _, f := range frames {
		assert.Empty(t, mullvadIDs(f.PeersChanged))
	}

	applyLikeClient(client, frames...)

	for _, id := range want {
		assert.Contains(t, client, id, "client lost synthetic peer %d", id)
		require.True(t, partialOnly(id), "synthetic peer %d left partialPeers", id)
	}

	// The viewer stops qualifying (here: no longer listed) before the full
	// is retried again. The retry's diff finds the synthetic peers in
	// partialPeers alone, and removes them ahead of the full.
	td.Config.Node.MullvadDirect = mullvadDirectFor(t, td.Config, key.NewNode().Public())
	require.NoError(t, handleNodeChange(nc, m, change.FullUpdate()))

	frames = drainResponses(older)
	require.Len(t, frames, 2, "a removal frame, then the full")
	assert.ElementsMatch(t, want, frames[0].PeersRemoved)
	require.NotNil(t, frames[1].Peers)
	assert.Empty(t, mullvadIDs(frames[1].Peers))
	applyLikeClient(client, frames...)

	for _, id := range want {
		assert.NotContains(t, client, id)

		_, partial := nc.partialPeers.Load(id)
		assert.False(t, partial, "partialPeers still holds synthetic peer %d after the removal and the full", id)
	}
}

// TestMullvadDirectBackpressureRetry drives upstream's retry of a full peer
// list sent while the session's queue has no room: the worker keeps the
// session, requeues the full, and the next tick renders it again from
// current state. If the viewer still qualifies, the retry must carry the
// synthetic peers and remove nothing. If it stopped qualifying while the
// full waited, the retry must remove them: nothing else will, as the
// requeued full absorbs the change that disqualified it.
func TestMullvadDirectBackpressureRetry(t *testing.T) {
	for _, qualifies := range []bool{true, false} {
		t.Run(fmt.Sprintf("qualifies-at-retry=%t", qualifies), func(t *testing.T) {
			td, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 2, normalBufferSize)
			defer cleanup()

			viewer := td.Nodes[0].n
			td.Config.Node.MullvadDirect = mullvadDirectFor(t, td.Config, viewer.NodeKey)

			want := mullvadIDs(mullvadDirectPeers(viewer.View(), td.Config))
			require.Len(t, want, 2)

			// Ticks run only through runTick.
			b := NewBatcher(time.Hour, 1, td.Batcher.mapper)

			b.Start()
			defer b.Close()

			// Room for a removal frame and the full.
			ch := make(chan *tailcfg.MapResponse, 2)
			require.NoError(t, b.AddNode(viewer.ID, ch, tailcfg.CurrentCapabilityVersion, nil))

			initial := expectReceive(t, ch, "initial map")
			require.ElementsMatch(t, want, mullvadIDs(initial.Peers))

			client := map[tailcfg.NodeID]*tailcfg.Node{}
			applyLikeClient(client, initial)

			nc, ok := b.nodes.Load(viewer.ID)
			require.True(t, ok)

			// The client stops reading with its queue full.
			for range cap(ch) {
				select {
				case ch <- testMapResponse():
				default:
					t.Fatal("client queue not empty before it was filled")
				}
			}

			b.AddWork(change.FullUpdate())
			runTick(t, b, nc)

			pending := getPendingForNode(b, viewer.ID)
			require.Len(t, pending, 1, "the blocked full must be requeued")
			require.True(t, pending[0].IsFull())
			require.Equal(t, 1, nc.getActiveConnectionCount(), "backpressure is not eviction")

			if !qualifies {
				// The viewer stops qualifying while its full waits (here: no
				// longer listed).
				td.Config.Node.MullvadDirect = mullvadDirectFor(t, td.Config, key.NewNode().Public())
			}

			// The client reads its full queue, which holds only the frames
			// that filled it; the next tick retries.
			drainResponses(ch)
			runTick(t, b, nc)

			frames := drainResponses(ch)
			require.NotEmpty(t, frames)
			applyLikeClient(client, frames...)

			full := frames[len(frames)-1]
			require.NotNil(t, full.Peers, "the retry renders a full peer list")
			assert.True(t, sortedByID(full.Peers))

			if qualifies {
				require.Len(t, frames, 1, "the retried full, with no removal frame")
				assert.ElementsMatch(t, want, mullvadIDs(full.Peers))
				assert.Equal(t, 1, taggedProfiles(full.UserProfiles))

				for _, id := range want {
					assert.Contains(t, client, id)
				}
			} else {
				require.Len(t, frames, 2, "a removal frame, then the retried full")
				assert.ElementsMatch(t, want, mullvadRemoved(frames))

				for _, f := range frames {
					assert.Empty(t, mullvadIDs(f.Peers), "the retry lists synthetic peers the viewer no longer gets")
				}

				for _, id := range want {
					assert.NotContains(t, client, id)
				}
			}

			assert.Empty(t, getPendingForNode(b, viewer.ID))
			assert.Zero(t, b.WorkErrors())
		})
	}
}

// TestMullvadDirectBacklogCollapse drives upstream's backlog cap: a backlog
// no tick drains, as behind busy workers, collapses past maxPendingSize to
// one full update, rendered when it drains. That full must carry the
// synthetic peers and remove nothing. Upstream's own tests pin the collapse;
// this pins that what it renders still goes through the full peer list.
func TestMullvadDirectBacklogCollapse(t *testing.T) {
	td, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 2, normalBufferSize)
	defer cleanup()

	viewer := td.Nodes[0].n
	td.Config.Node.MullvadDirect = mullvadDirectFor(t, td.Config, viewer.NodeKey)

	want := mullvadIDs(mullvadDirectPeers(viewer.View(), td.Config))
	require.Len(t, want, 2)

	// Ticks run only through runTick.
	b := NewBatcher(time.Hour, 1, td.Batcher.mapper)

	b.Start()
	defer b.Close()

	ch := make(chan *tailcfg.MapResponse, normalBufferSize)
	require.NoError(t, b.AddNode(viewer.ID, ch, tailcfg.CurrentCapabilityVersion, nil))

	client := map[tailcfg.NodeID]*tailcfg.Node{}
	applyLikeClient(client, expectReceive(t, ch, "initial map"))

	nc, ok := b.nodes.Load(viewer.ID)
	require.True(t, ok)

	// A peer flaps. A fold keeps every patch, so maxPendingSize of them
	// outgrow the cap however often they fold first.
	peer := td.Nodes[1].n.ID

	for i := range maxPendingSize {
		if i%2 == 0 {
			b.AddWork(change.NodeOnline(peer))
		} else {
			b.AddWork(change.NodeOffline(peer))
		}
	}

	pending := getPendingForNode(b, viewer.ID)
	require.Len(t, pending, 1, "the backlog must collapse")
	require.True(t, pending[0].IsFull())

	runTick(t, b, nc)

	frames := drainResponses(ch)
	require.Len(t, frames, 1, "the collapsed full, with no removal frame")

	full := frames[0]
	assert.ElementsMatch(t, want, mullvadIDs(full.Peers))
	assert.True(t, sortedByID(full.Peers))
	assert.Equal(t, 1, taggedProfiles(full.UserProfiles))
	applyLikeClient(client, frames...)

	for _, id := range want {
		assert.Contains(t, client, id)
	}

	assert.Zero(t, b.WorkErrors())
}

// TestMullvadDirectRekeyedViewerLosesPeers: a listed device that logs in
// again with a new node key is no longer listed. Its old stream ends, it
// polls again with the new key, and the new stream's initial map omits the
// synthetic peers. Here that map lists no peers at all, which clients take
// as no change, so AddNode must follow it with the removal of what the old
// stream had. AddNode queues that removal and keeps the removed peers
// tracked, so a full that supersedes the queued removal removes them too.
func TestMullvadDirectRekeyedViewerLosesPeers(t *testing.T) {
	for _, superseded := range []bool{false, true} {
		t.Run(fmt.Sprintf("removal-superseded-by-full=%t", superseded), func(t *testing.T) {
			td, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 1, normalBufferSize)
			defer cleanup()

			viewer := td.Nodes[0].n
			td.Config.Node.MullvadDirect = mullvadDirectFor(t, td.Config, viewer.NodeKey)

			want := mullvadIDs(mullvadDirectPeers(viewer.View(), td.Config))
			require.Len(t, want, 2)

			// Ticks run only through runTick.
			b := NewBatcher(time.Hour, 1, td.Batcher.mapper)

			b.Start()
			defer b.Close()

			capVer := tailcfg.CurrentCapabilityVersion
			ch1 := make(chan *tailcfg.MapResponse, normalBufferSize)
			require.NoError(t, b.AddNode(viewer.ID, ch1, capVer, nil))

			initial := expectReceive(t, ch1, "initial map")
			require.ElementsMatch(t, want, mullvadIDs(initial.Peers))
			require.Len(t, initial.Peers, len(want), "the synthetic peers are the viewer's only peers")

			client := map[tailcfg.NodeID]*tailcfg.Node{}
			applyLikeClient(client, initial)

			// The device logs in again with a new node key. The relogin's
			// own change is not queued: here it is an update from the viewer
			// itself (OriginNode), which the viewer gets as a self-only
			// response with no peer list, so only AddNode removes the
			// synthetic peers.
			uid := types.UserID(td.Users[0].ID)
			pak, err := td.State.CreatePreAuthKey(&uid, true, false, nil, nil)
			require.NoError(t, err)

			newKey := key.NewNode().Public()
			nv, _, err := td.State.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
				Auth:       &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
				NodeKey:    newKey,
				OldNodeKey: viewer.NodeKey,
				Hostinfo:   &tailcfg.Hostinfo{Hostname: viewer.Hostname},
			}, viewer.MachineKey)
			require.NoError(t, err)
			require.Equal(t, viewer.ID, nv.ID(), "the relogin keeps the node")
			require.Equal(t, newKey, nv.NodeKey())
			require.False(t, nv.IsTagged(), "only the key change disqualifies it")
			require.Nil(t, mullvadDirectIDs(nv, td.Config), "the new key is not listed")

			// Its old stream ends, and it polls again with the new key.
			b.RemoveNode(viewer.ID, ch1)

			ch2 := make(chan *tailcfg.MapResponse, normalBufferSize)
			require.NoError(t, b.AddNode(viewer.ID, ch2, capVer, nil))

			initial = expectReceive(t, ch2, "initial map after the relogin")
			require.NotNil(t, initial.Peers, "a full map")
			require.Empty(t, initial.Peers, "the new key gets no synthetic peers")

			// The client keeps the synthetic peers: an empty peer list is no
			// change to it.
			applyLikeClient(client, initial)

			// AddNode diffed the new map against what the old stream had and
			// queued the removal for the next tick.
			nc, ok := b.nodes.Load(viewer.ID)
			require.True(t, ok)

			pending := getPendingForNode(b, viewer.ID)
			require.Len(t, pending, 1, "the reconnect must queue the removal")
			assert.Equal(t, viewer.ID, pending[0].TargetNode)

			queued := make([]tailcfg.NodeID, 0, len(pending[0].PeersRemoved))
			for _, id := range pending[0].PeersRemoved {
				queued = append(queued, id.NodeID())
			}

			assert.ElementsMatch(t, want, queued)

			if superseded {
				// A full arrives before the tick and supersedes the queued
				// removal. Its peer list is empty too, so its own diff must
				// remove the synthetic peers, which AddNode kept tracked.
				b.AddWork(change.FullUpdate())

				pending = getPendingForNode(b, viewer.ID)
				require.Len(t, pending, 1)
				require.True(t, pending[0].IsFull(), "the full supersedes the queued removal")
			}

			runTick(t, b, nc)

			frames := drainResponses(ch2)
			assert.ElementsMatch(t, want, mullvadRemoved(frames))
			applyLikeClient(client, frames...)

			for _, id := range want {
				assert.NotContains(t, client, id)
			}

			// Removed once: a later full neither lists nor removes them.
			b.AddWork(change.FullUpdate())
			runTick(t, b, nc)

			frames = drainResponses(ch2)
			require.NotEmpty(t, frames)
			assert.Empty(t, mullvadRemoved(frames))

			for _, f := range frames {
				assert.Empty(t, mullvadIDs(f.Peers))
			}
		})
	}
}
