package mapper

import (
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/dnstype"
)

// mullvadDirectTag marks the synthetic peers as tagged, like every other
// node headscale presents as owned by the tagged-devices user. The tag
// exists only in clients' netmaps; the policy never sees it.
const mullvadDirectTag = "tag:mullvad-direct"

// mullvadDirectDevice returns the viewer's Mullvad device if the viewer may
// use node.mullvad_direct: listed by node key and not tagged.
func mullvadDirectDevice(viewer types.NodeView, cfg *types.Config) (types.MullvadDevice, bool) {
	// NodeView.NodeKey dereferences without a check.
	if cfg == nil || cfg.Node.MullvadDirect == nil || !viewer.Valid() || viewer.IsTagged() {
		return types.MullvadDevice{}, false
	}

	dev, ok := cfg.Node.MullvadDirect.Devices[viewer.NodeKey()]

	return dev, ok
}

// mullvadDirectIDs returns the IDs of the synthetic peers viewer gets.
func mullvadDirectIDs(viewer types.NodeView, cfg *types.Config) []tailcfg.NodeID {
	if _, ok := mullvadDirectDevice(viewer, cfg); !ok {
		return nil
	}

	ids := make([]tailcfg.NodeID, 0, len(cfg.Node.MullvadDirect.Servers))
	for _, s := range cfg.Node.MullvadDirect.Servers {
		ids = append(ids, s.ID)
	}

	return ids
}

// mullvadDirectPeers returns, for a viewer that may use node.mullvad_direct,
// one WireGuard-only exit-node peer per Mullvad city, dressed the way
// Tailscale dresses its own Mullvad nodes so clients list them by country
// and city. They go into every full peer list and never into a delta. Each
// call builds fresh nodes, because the masquerade addresses belong to the
// viewer.
func mullvadDirectPeers(viewer types.NodeView, cfg *types.Config) []*tailcfg.Node {
	dev, ok := mullvadDirectDevice(viewer, cfg)
	if !ok {
		return nil
	}

	md := cfg.Node.MullvadDirect
	peers := make([]*tailcfg.Node, 0, len(md.Servers))

	for _, s := range md.Servers {
		loc := s.Location
		hi := tailcfg.Hostinfo{Hostname: s.Hostname, Location: &loc}
		online := true
		v4, v6 := dev.IPv4, dev.IPv6

		allowedIPs := []netip.Prefix{s.Addr4, s.Addr6, tsaddr.AllIPv4(), tsaddr.AllIPv6()}
		slices.SortFunc(allowedIPs, netip.Prefix.Compare)

		peers = append(peers, &tailcfg.Node{
			ID:       s.ID,
			StableID: s.StableID,
			Name:     s.Name,
			// Not the viewer's user: clients trust a peer of their own
			// user as one of their own devices (peerapi, Taildrop).
			User:       tailcfg.UserID(types.TaggedDevicesUserID),
			Tags:       []string{mullvadDirectTag},
			Key:        s.Key,
			Addresses:  []netip.Prefix{s.Addr4, s.Addr6},
			AllowedIPs: allowedIPs,
			Endpoints:  []netip.AddrPort{s.Endpoint},
			Hostinfo:   hi.View(),
			// Apple clients offer exit nodes from suggestion candidates.
			CapMap:            tailcfg.NodeCapMap{nodecap.SuggestExitNode: nil},
			Online:            &online,
			MachineAuthorized: true,
			IsWireGuardOnly:   true,
			IsJailed:          true,
			// Cap stays 0: from 26 up, clients expect a peerapi DNS
			// proxy on the exit node, and DNS breaks.
			SelfNodeV4MasqAddrForThisPeer: &v4,
			SelfNodeV6MasqAddrForThisPeer: &v6,
			ExitNodeDNSResolvers:          []*dnstype.Resolver{{Addr: md.DNS.String()}},
		})
	}

	return peers
}
