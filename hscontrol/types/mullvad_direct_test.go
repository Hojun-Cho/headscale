package types

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func testMullvadKey() string {
	k := key.NewNode().Public().Raw32()

	return base64.StdEncoding.EncodeToString(k[:])
}

func testMullvadRelay(host, country, city, ip string, owned bool) map[string]any {
	return map[string]any{
		"hostname":     host,
		"country_name": country,
		"city_name":    city,
		"active":       true,
		"owned":        owned,
		"type":         "wireguard",
		"pubkey":       testMullvadKey(),
		"ipv4_addr_in": ip,
	}
}

func testMullvadDevices() []MullvadDeviceConfig {
	return []MullvadDeviceConfig{{
		Name: "dev", NodeKey: key.NewNode().Public().String(), IPv4: "10.124.0.1", IPv6: "fc00:bbbb:bbbb:bb01::1",
	}}
}

func testMullvadJSON(t *testing.T, entries ...any) []byte {
	t.Helper()

	b, err := json.Marshal(entries)
	require.NoError(t, err)

	return b
}

func testMullvadPrefixes() (*netip.Prefix, *netip.Prefix) {
	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	return &p4, &p6
}

func testMullvadCityID(cityKey string) tailcfg.NodeID {
	h := fnv.New32a()
	h.Write([]byte(cityKey))

	return MullvadDirectIDBase + tailcfg.NodeID(h.Sum32())
}

func testMullvadPub(t *testing.T, b64 any) key.NodePublic {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(b64.(string))
	require.NoError(t, err)

	var k key.NodePublic
	require.NoError(t, k.UnmarshalText([]byte("nodekey:"+hex.EncodeToString(raw))))

	return k
}

func testMullvadByCity(t *testing.T, md *MullvadDirect) map[string]MullvadServer {
	t.Helper()

	byCity := make(map[string]MullvadServer)

	for _, s := range md.Servers {
		city, ok := strings.CutPrefix(string(s.StableID), "mullvad-")
		require.True(t, ok, s.StableID)
		byCity[city] = s
	}

	return byCity
}

func TestMullvadDirectParse(t *testing.T) {
	p4, p6 := testMullvadPrefixes()
	devKey := key.NewNode().Public()

	tyo1 := testMullvadRelay("jp-tyo-wg-001", "Japan", "Tokyo", "192.0.2.1", false)
	tyo2 := testMullvadRelay("jp-tyo-wg-002", "Japan", "Tokyo", "192.0.2.2", true)
	tyo3 := testMullvadRelay("jp-tyo-wg-201", "Japan", "Tokyo", "192.0.2.3", false)
	osa := testMullvadRelay("jp-osa-wg-101", "Japan", "Osaka", "192.0.2.4", true)
	fiHel := testMullvadRelay("fi-hel-wg-001", "Finland", "Helsinki", "192.0.2.6", false)
	seHel := testMullvadRelay("se-hel-wg-001", "Sweden", "Hel", "192.0.2.7", false)

	// Two entries share a hostname. The one with the smaller pubkey must
	// win, even though the other is owned and would otherwise be picked.
	atl := testMullvadRelay("us-atl-wg-001", "USA", "Atlanta, GA", "192.0.2.5", false)
	atlDup := testMullvadRelay("us-atl-wg-001", "USA", "Atlanta, GA", "192.0.2.50", false)

	atlKey := atl["pubkey"].(string)
	if atlDup["pubkey"].(string) < atlKey {
		atlKey = atlDup["pubkey"].(string)
		atl["owned"] = true
	} else {
		atlDup["owned"] = true
	}

	// Cross-city duplicates that sort after their originals and are owned:
	// if kept, they would become their city's pick.
	keyReuse := testMullvadRelay("us-atl-wg-002", "USA", "Atlanta, GA", "192.0.2.51", true)
	keyReuse["pubkey"] = osa["pubkey"]
	addrReuse := testMullvadRelay("se-hel-wg-002", "Sweden", "Hel", "192.0.2.2", true)

	// Pairs that agree on hostname and pubkey and differ elsewhere. The
	// tie-breakers decide which one is kept, whatever the list order; the
	// list holds the losing one first.
	amsA := testMullvadRelay("nl-ams-wg-001", "Netherlands", "Amsterdam", "192.0.2.70", false)
	amsB := maps.Clone(amsA)
	amsB["ipv4_addr_in"] = "192.0.2.71"
	berA := testMullvadRelay("de-ber-wg-001", "Germany", "Berlin", "192.0.2.80", false)
	berB := maps.Clone(berA)
	berB["country_name"], berB["city_name"] = "Germany B", "Berlin B"

	// Each must be skipped for one reason. Each sits in a city of its own
	// (zz-sNN), so a rule that stops skipping shows up as a new city.
	var skipped []any

	for i, mutate := range []func(map[string]any){
		func(r map[string]any) { r["active"] = false },
		func(r map[string]any) { r["type"] = "bridge" },
		func(r map[string]any) { r["active"] = "yes" },
		func(r map[string]any) { r["pubkey"] = "not base64!" },
		func(r map[string]any) { r["pubkey"] = base64.StdEncoding.EncodeToString(make([]byte, 31)) },
		func(r map[string]any) { r["pubkey"] = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
		func(r map[string]any) { r["ipv4_addr_in"] = "2001:db8::1" },
		func(r map[string]any) { r["ipv4_addr_in"] = "10.1.2.3" },
		func(r map[string]any) { r["ipv4_addr_in"] = "100.64.0.9" },
		func(r map[string]any) { r["ipv4_addr_in"] = "not an ip" },
		func(r map[string]any) { r["country_name"] = "" },
		func(r map[string]any) { r["city_name"] = "" },
		func(r map[string]any) { r["city_name"] = "Null\x00City" },
		func(r map[string]any) { r["country_name"] = "Bidi‮land" },
		func(r map[string]any) { r["city_name"] = strings.Repeat("x", 65) },
		func(r map[string]any) { r["city_name"] = "Bad \uFFFD Name" },
		func(r map[string]any) { r["hostname"] = r["hostname"].(string) + "-" },
		func(r map[string]any) { r["hostname"] = r["hostname"].(string) + strings.Repeat("x", 60) },
	} {
		r := testMullvadRelay(fmt.Sprintf("zz-s%02d-wg-001", i), "Testland", "Skip City",
			fmt.Sprintf("198.51.100.%d", i+1), true)
		mutate(r)
		skipped = append(skipped, r)
	}

	skipped = append(skipped,
		42,
		testMullvadRelay("tokyo-1", "Japan", "Tokyo", "198.51.100.200", true),
		testMullvadRelay("zz-sbr-br-001", "Testland", "Skip City", "198.51.100.201", true),
	)

	entries := slices.Concat(
		[]any{tyo1, tyo2, tyo3, osa, atl, atlDup, fiHel, seHel, keyReuse, addrReuse, amsB, amsA, berB, berA},
		skipped,
	)

	cfg := MullvadDirectConfig{
		DNS:         "10.64.0.1",
		DefaultCity: "jp-tyo",
		Devices: []MullvadDeviceConfig{{
			Name:    "iphone",
			NodeKey: devKey.String(),
			IPv4:    "10.124.0.1/32",
			IPv6:    "fc00:bbbb:bbbb:bb01:d:0:a:1/128",
		}},
	}

	md, err := cfg.Parse(testMullvadJSON(t, entries...), p4, p6, IPAllocationStrategySequential)
	require.NoError(t, err)

	assert.Equal(t, netip.MustParseAddr("10.64.0.1"), md.DNS)
	assert.Equal(t, map[key.NodePublic]MullvadDevice{devKey: {
		Name: "iphone",
		IPv4: netip.MustParseAddr("10.124.0.1"),
		IPv6: netip.MustParseAddr("fc00:bbbb:bbbb:bb01:d:0:a:1"),
	}}, md.Devices)

	byCity := testMullvadByCity(t, md)
	assert.ElementsMatch(t, []string{"jp-tyo", "jp-osa", "us-atl", "fi-hel", "se-hel", "nl-ams", "de-ber"},
		slices.Collect(maps.Keys(byCity)), "one server per city, no skipped entry")

	seen4 := make(map[netip.Prefix]bool)
	seen6 := make(map[netip.Prefix]bool)

	for i, s := range md.Servers {
		if i > 0 {
			assert.Less(t, md.Servers[i-1].ID, s.ID, "servers sorted by ID")
		}

		city := strings.TrimPrefix(string(s.StableID), "mullvad-")
		assert.True(t, IsMullvadDirectID(s.ID))
		assert.Equal(t, testMullvadCityID(city), s.ID)
		assert.Equal(t, s.Hostname+".mullvad.ts.net.", s.Name)
		assert.Equal(t, uint16(51820), s.Endpoint.Port())

		assert.Equal(t, netip.AddrFrom4([4]byte{100, 127, 0, byte(i + 1)}), s.Addr4.Addr())
		assert.Equal(t, 32, s.Addr4.Bits())
		assert.Equal(t, 128, s.Addr6.Bits())
		assert.True(t, netip.MustParsePrefix("fd7a:115c:a1e0:ffff::/64").Contains(s.Addr6.Addr()))
		assert.False(t, seen4[s.Addr4] || seen6[s.Addr6], "addresses unique")
		seen4[s.Addr4], seen6[s.Addr6] = true, true
	}

	tyo := byCity["jp-tyo"]
	assert.Equal(t, "jp-tyo-wg-002", tyo.Hostname, "the owned server wins")
	assert.Equal(t, testMullvadPub(t, tyo2["pubkey"]), tyo.Key)
	assert.Equal(t, netip.MustParseAddrPort("192.0.2.2:51820"), tyo.Endpoint)
	assert.Equal(t, tailcfg.Location{
		Country: "Japan", CountryCode: "JP", City: "Tokyo", CityCode: "TYO", Priority: 3,
	}, tyo.Location)

	assert.Equal(t, tailcfg.Location{
		Country: "Japan", CountryCode: "JP", City: "Osaka", CityCode: "OSA", Priority: 1,
	}, byCity["jp-osa"].Location)
	assert.Equal(t, testMullvadPub(t, osa["pubkey"]), byCity["jp-osa"].Key)

	atlanta := byCity["us-atl"]
	assert.Equal(t, testMullvadPub(t, atlKey), atlanta.Key,
		"duplicate hostname: the smaller pubkey wins; a reused key in another city is dropped")
	assert.Equal(t, tailcfg.Location{
		Country: "USA", CountryCode: "US", City: "Atlanta, GA", CityCode: "ATL", Priority: 2,
	}, atlanta.Location)

	assert.Equal(t, "se-hel-wg-001", byCity["se-hel"].Hostname, "a reused address in another city is dropped")
	assert.Equal(t, "SE-HEL", byCity["se-hel"].Location.CityCode, "label shared by two countries")
	assert.Equal(t, "FI-HEL", byCity["fi-hel"].Location.CityCode)
	assert.Equal(t, 2, byCity["fi-hel"].Location.Priority)

	assert.Equal(t, netip.MustParseAddrPort("192.0.2.70:51820"), byCity["nl-ams"].Endpoint, "address tie-break")
	assert.Equal(t, "Germany", byCity["de-ber"].Location.Country, "name tie-break")
	assert.Equal(t, "Berlin", byCity["de-ber"].Location.City)

	t.Run("order-independent", func(t *testing.T) {
		reversed := slices.Clone(entries)
		slices.Reverse(reversed)

		md2, err := cfg.Parse(testMullvadJSON(t, reversed...), p4, p6, IPAllocationStrategySequential)
		require.NoError(t, err)
		assert.Equal(t, md, md2)
	})

	t.Run("bare-device-addresses", func(t *testing.T) {
		bare := cfg
		bare.Devices = []MullvadDeviceConfig{{
			Name: "iphone", NodeKey: devKey.String(), IPv4: "10.124.0.1", IPv6: "fc00:bbbb:bbbb:bb01:d:0:a:1",
		}}

		md2, err := bare.Parse(testMullvadJSON(t, entries...), p4, p6, IPAllocationStrategySequential)
		require.NoError(t, err)
		assert.Equal(t, md.Devices, md2.Devices)
	})

	t.Run("server-swap-keeps-city-id", func(t *testing.T) {
		without := slices.DeleteFunc(slices.Clone(entries), func(e any) bool {
			r, ok := e.(map[string]any)
			return ok && r["hostname"] == "jp-tyo-wg-002"
		})

		md2, err := cfg.Parse(testMullvadJSON(t, without...), p4, p6, IPAllocationStrategySequential)
		require.NoError(t, err)

		swapped := testMullvadByCity(t, md2)["jp-tyo"]
		assert.Equal(t, tyo.ID, swapped.ID)
		assert.Equal(t, tyo.StableID, swapped.StableID)
		assert.Equal(t, "jp-tyo-wg-001", swapped.Hostname)
		assert.NotEqual(t, tyo.Key, swapped.Key)
		assert.NotEqual(t, tyo.Name, swapped.Name)
	})
}

func TestMullvadDirectParseIDCollision(t *testing.T) {
	p4, p6 := testMullvadPrefixes()

	// These two city keys hash to the same FNV-32a value.
	require.Equal(t, testMullvadCityID("jp-55pugl"), testMullvadCityID("jp-zje3b"))

	relays := testMullvadJSON(t,
		testMullvadRelay("jp-55pugl-wg-001", "Japan", "Alpha", "192.0.2.1", false),
		testMullvadRelay("jp-zje3b-wg-001", "Japan", "Beta", "192.0.2.2", false),
		testMullvadRelay("jp-zje3b-wg-002", "Japan", "Beta", "192.0.2.3", false),
		testMullvadRelay("jp-osa-wg-001", "Japan", "Osaka", "192.0.2.4", false),
	)

	md, err := MullvadDirectConfig{DNS: "10.64.0.1", DefaultCity: "jp-osa", Devices: testMullvadDevices()}.
		Parse(relays, p4, p6, IPAllocationStrategySequential)
	require.NoError(t, err)

	byCity := testMullvadByCity(t, md)
	require.Len(t, byCity, 2, "the later colliding city is dropped")
	assert.NotContains(t, byCity, "jp-zje3b")
	// With jp-zje3b gone, jp-55pugl and jp-osa have one server each: the
	// tie goes to the smaller key, and the default stays on top.
	assert.Equal(t, 2, byCity["jp-55pugl"].Location.Priority)
	assert.Equal(t, 3, byCity["jp-osa"].Location.Priority)

	_, err = MullvadDirectConfig{DNS: "10.64.0.1", DefaultCity: "jp-zje3b", Devices: testMullvadDevices()}.
		Parse(relays, p4, p6, IPAllocationStrategySequential)
	require.ErrorContains(t, err, "default_city", "a dropped default city is an error")
}

func TestMullvadDirectParseManyCities(t *testing.T) {
	p4, p6 := testMullvadPrefixes()

	var relays []any
	for i := range 300 {
		relays = append(relays, testMullvadRelay(
			fmt.Sprintf("xx-c%d-wg-001", i), "Testland", fmt.Sprintf("City %d", i),
			netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}).Next().String(), false))
	}

	md, err := MullvadDirectConfig{DNS: "10.64.0.1", DefaultCity: "xx-c0", Devices: testMullvadDevices()}.
		Parse(testMullvadJSON(t, relays...), p4, p6, IPAllocationStrategySequential)
	require.NoError(t, err)
	require.Len(t, md.Servers, 300)

	block4 := netip.MustParsePrefix("100.127.0.0/16")
	block6 := netip.MustParsePrefix("fd7a:115c:a1e0:ffff::/64")
	seen := make(map[netip.Addr]bool)

	for _, s := range md.Servers {
		for _, a := range []netip.Addr{s.Addr4.Addr(), s.Addr6.Addr()} {
			assert.False(t, seen[a], "address %s used twice", a)
			seen[a] = true
		}

		assert.True(t, block4.Contains(s.Addr4.Addr()), s.Addr4)
		assert.True(t, block6.Contains(s.Addr6.Addr()), s.Addr6)
		assert.NotEqual(t, byte(0), s.Addr4.Addr().As4()[3], "no .0 addresses")
		assert.NotEqual(t, byte(255), s.Addr4.Addr().As4()[3], "no .255 addresses")
	}

	assert.Equal(t, netip.MustParseAddr("100.127.1.1"), md.Servers[254].Addr4.Addr(), "rolls over after 254")
}

func TestMullvadDirectReadRelaysSizeCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relays.json")
	require.NoError(t, os.WriteFile(path, make([]byte, mullvadMaxRelaysFile+1), 0o600))

	_, err := readMullvadFile(path, "relays_path", mullvadMaxRelaysFile)
	require.ErrorContains(t, err, "larger than")
}

func TestMullvadDirectParseErrors(t *testing.T) {
	p4, p6 := testMullvadPrefixes()
	good := testMullvadJSON(t, testMullvadRelay("jp-tyo-wg-001", "Japan", "Tokyo", "192.0.2.1", true))
	devKey := key.NewNode().Public()

	var tooMany []any
	for i := range mullvadMaxCities + 1 {
		tooMany = append(tooMany, testMullvadRelay(
			fmt.Sprintf("xx-c%d-wg-001", i), "Testland", fmt.Sprintf("City %d", i),
			netip.AddrFrom4([4]byte{198, 18 + byte(i>>8), byte(i), 1}).String(), false))
	}

	device := func(mutate func(*MullvadDeviceConfig)) func(*MullvadDirectConfig) {
		return func(c *MullvadDirectConfig) {
			d := MullvadDeviceConfig{Name: "dev", NodeKey: devKey.String(), IPv4: "10.124.0.1/32", IPv6: "fc00:bbbb:bbbb:bb01::1/128"}
			mutate(&d)
			c.Devices = []MullvadDeviceConfig{d}
		}
	}

	narrow4 := netip.MustParsePrefix("100.64.0.0/16")
	narrow6 := netip.MustParsePrefix("fd7a:115c:a1e0:ffff::/64")

	tests := []struct {
		name     string
		relays   []byte
		mutate   func(*MullvadDirectConfig)
		alloc    IPAllocationStrategy
		prefix4  *netip.Prefix
		prefix6  *netip.Prefix
		noPrefix bool
		want     string
	}{
		{name: "not-json", relays: []byte("{"), want: "not a JSON array"},
		{name: "object", relays: []byte(`{"hostname":"jp-tyo-wg-001"}`), want: "not a JSON array"},
		{name: "empty", relays: []byte("[]"), want: "no active WireGuard server"},
		{name: "all-skipped", relays: testMullvadJSON(t, map[string]any{"hostname": "jp-tyo-wg-001", "active": false}), want: "no active WireGuard server"},
		{name: "too-many-cities", relays: testMullvadJSON(t, tooMany...), mutate: func(c *MullvadDirectConfig) { c.DefaultCity = "xx-c0" }, want: "more than 1024"},
		{name: "no-devices", mutate: func(c *MullvadDirectConfig) { c.Devices = nil }, want: "at least one device"},
		{name: "no-default-city", mutate: func(c *MullvadDirectConfig) { c.DefaultCity = "" }, want: "default_city is required"},
		{name: "unknown-default-city", mutate: func(c *MullvadDirectConfig) { c.DefaultCity = "xx-nowhere" }, want: "default_city"},
		{name: "random-alloc", alloc: IPAllocationStrategyRandom, want: "allocation"},
		{name: "no-prefixes", noPrefix: true, want: "prefixes"},
		{name: "narrow-v4-prefix", prefix4: &narrow4, want: "prefixes"},
		{name: "synthetic-v6-prefix", prefix6: &narrow6, want: "prefixes"},
		{name: "dns-not-an-ip", mutate: func(c *MullvadDirectConfig) { c.DNS = "resolver" }, want: "dns"},
		{name: "dns-ipv6", mutate: func(c *MullvadDirectConfig) { c.DNS = "fc00::1" }, want: "dns"},
		{name: "dns-in-tailnet", mutate: func(c *MullvadDirectConfig) { c.DNS = "100.64.0.7" }, want: "dns"},
		{name: "device-no-name", mutate: device(func(d *MullvadDeviceConfig) { d.Name = "" }), want: "name is empty"},
		{name: "node-key-no-prefix", mutate: device(func(d *MullvadDeviceConfig) { d.NodeKey = strings.TrimPrefix(d.NodeKey, "nodekey:") }), want: "node_key"},
		{name: "node-key-short", mutate: device(func(d *MullvadDeviceConfig) { d.NodeKey = "nodekey:abcd" }), want: "node_key"},
		{name: "node-key-zero", mutate: device(func(d *MullvadDeviceConfig) { d.NodeKey = "nodekey:" + strings.Repeat("0", 64) }), want: "node_key"},
		{name: "ipv4-holds-ipv6", mutate: device(func(d *MullvadDeviceConfig) { d.IPv4 = "fc00:bbbb:bbbb:bb01::1" }), want: "ipv4"},
		{name: "ipv4-4in6", mutate: device(func(d *MullvadDeviceConfig) { d.IPv4 = "::ffff:10.124.0.1" }), want: "ipv4"},
		{name: "ipv4-not-single", mutate: device(func(d *MullvadDeviceConfig) { d.IPv4 = "10.124.0.0/24" }), want: "ipv4"},
		{name: "ipv6-holds-ipv4", mutate: device(func(d *MullvadDeviceConfig) { d.IPv6 = "10.124.0.2" }), want: "ipv6"},
		{name: "ipv6-4in6", mutate: device(func(d *MullvadDeviceConfig) { d.IPv6 = "::ffff:10.124.0.2" }), want: "ipv6"},
		{name: "ipv6-zone", mutate: device(func(d *MullvadDeviceConfig) { d.IPv6 = "fe80::1%eth0" }), want: "ipv6"},
		{name: "duplicate-node-key", mutate: func(c *MullvadDirectConfig) {
			d := MullvadDeviceConfig{Name: "a", NodeKey: devKey.String(), IPv4: "10.124.0.1", IPv6: "fc00:bbbb:bbbb:bb01::1"}
			e := d
			e.Name, e.IPv4, e.IPv6 = "b", "10.124.0.2", "fc00:bbbb:bbbb:bb01::2"
			c.Devices = []MullvadDeviceConfig{d, e}
		}, want: "duplicate node_key"},
		{name: "duplicate-address", mutate: func(c *MullvadDirectConfig) {
			d := MullvadDeviceConfig{Name: "a", NodeKey: devKey.String(), IPv4: "10.124.0.1", IPv6: "fc00:bbbb:bbbb:bb01::1"}
			e := d
			e.Name, e.NodeKey, e.IPv6 = "b", key.NewNode().Public().String(), "fc00:bbbb:bbbb:bb01::2"
			c.Devices = []MullvadDeviceConfig{d, e}
		}, want: "already used"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := MullvadDirectConfig{DNS: "10.64.0.1", DefaultCity: "jp-tyo", Devices: testMullvadDevices()}
			if tt.mutate != nil {
				tt.mutate(&cfg)
			}

			relays := tt.relays
			if relays == nil {
				relays = good
			}

			alloc := tt.alloc
			if alloc == "" {
				alloc = IPAllocationStrategySequential
			}

			v4, v6 := p4, p6
			if tt.prefix4 != nil {
				v4 = tt.prefix4
			}

			if tt.prefix6 != nil {
				v6 = tt.prefix6
			}

			if tt.noPrefix {
				v4, v6 = nil, nil
			}

			md, err := cfg.Parse(relays, v4, v6, alloc)
			require.Error(t, err)
			assert.Nil(t, md)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestMullvadDirectConfigLoad(t *testing.T) {
	devKey := key.NewNode().Public()
	relays := testMullvadJSON(t,
		testMullvadRelay("jp-tyo-wg-001", "Japan", "Tokyo", "192.0.2.1", true),
		testMullvadRelay("jp-osa-wg-001", "Japan", "Osaka", "192.0.2.2", true),
	)
	block := fmt.Sprintf(`node:
  mullvad_direct:
    dns: "10.64.0.1"
    relays_path: "mullvad-relays.json"
    default_city: "jp-tyo"
    devices:
      - name: "iphone"
        node_key: "%s"
        ipv4: "10.124.0.1/32"
        ipv6: "fc00:bbbb:bbbb:bb01::1/128"
        mullvad_device: "just gerbil"
`, devKey)

	fileBlock := `node:
  mullvad_direct:
    dns: "10.64.0.1"
    relays_path: "mullvad-relays.json"
    default_city: "jp-tyo"
    devices_path: "mullvad-devices.json"
`
	devicesJSON := fmt.Sprintf(`[{"name": "iphone", "node_key": "%s", "ipv4": "10.124.0.1/32",
  "ipv6": "fc00:bbbb:bbbb:bb01::1/128", "mullvad_device": "just gerbil"}]`, devKey)

	tests := []struct {
		name        string
		yaml        string
		writeRelays bool
		devicesJSON string
		wantErr     string
		wantServers int
	}{
		{name: "absent"},
		{name: "valid", yaml: block, writeRelays: true, wantServers: 2},
		{name: "missing-relays-file", yaml: block, wantErr: "relays_path"},
		{name: "bad-node-key", yaml: strings.Replace(block, devKey.String(), "nodekey:abcd", 1), writeRelays: true, wantErr: "node_key"},
		{name: "misspelt-key", yaml: strings.Replace(block, "default_city", "default-city", 1), writeRelays: true, wantErr: "unknown key"},
		{name: "misspelt-device-key", yaml: strings.Replace(block, "ipv4:", "ipv44:", 1), writeRelays: true, wantErr: "unknown key"},
		{name: "dedented-devices", yaml: strings.Replace(block, "    devices:", "  devices:", 1), writeRelays: true, wantErr: "at least one device"},
		{name: "devices-file", yaml: fileBlock, writeRelays: true, devicesJSON: devicesJSON, wantServers: 2},
		{name: "devices-file-missing", yaml: fileBlock, writeRelays: true, wantErr: "devices_path"},
		{name: "devices-file-unknown-field", yaml: fileBlock, writeRelays: true, devicesJSON: strings.Replace(devicesJSON, `"ipv4"`, `"ipv44"`, 1), wantErr: "devices_path: json: unknown field"},
		{name: "devices-file-empty", yaml: fileBlock, writeRelays: true, devicesJSON: "[]", wantErr: "devices_path: list at least one device"},
		{name: "devices-file-null", yaml: fileBlock, writeRelays: true, devicesJSON: "null", wantErr: "devices_path: list at least one device"},
		{name: "devices-file-object", yaml: fileBlock, writeRelays: true, devicesJSON: "{}", wantErr: "devices_path: json"},
		{name: "devices-file-trailing", yaml: fileBlock, writeRelays: true, devicesJSON: devicesJSON + "]", wantErr: "data after the array"},
		{name: "devices-file-two-arrays", yaml: fileBlock, writeRelays: true, devicesJSON: devicesJSON + "\n[]", wantErr: "data after the array"},
		{name: "devices-file-too-big", yaml: fileBlock, writeRelays: true, devicesJSON: strings.Repeat(" ", mullvadMaxDevicesFile+1), wantErr: "devices_path: larger than"},
		{name: "devices-and-file", yaml: block + "    devices_path: \"mullvad-devices.json\"\n", writeRelays: true, devicesJSON: devicesJSON, wantErr: "not both"},
		{name: "empty-block", yaml: "node:\n  mullvad_direct:\n  #  dns: \"10.64.0.1\"\n", wantErr: "empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()

			tmpDir := t.TempDir()
			cfg := `---
server_url: https://example.com
listen_addr: 0.0.0.0:8080
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
noise:
  private_key_path: noise_private.key
database:
  type: sqlite3
dns:
  magic_dns: false
  override_local_dns: false
` + tt.yaml + "\n"
			require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(cfg), 0o600))

			if tt.writeRelays {
				require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "mullvad-relays.json"), relays, 0o600))
			}

			if tt.devicesJSON != "" {
				require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "mullvad-devices.json"), []byte(tt.devicesJSON), 0o600))
			}

			require.NoError(t, LoadConfig(tmpDir, false))

			got, err := LoadServerConfig()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "node.mullvad_direct")
				assert.Contains(t, err.Error(), tt.wantErr)

				return
			}

			require.NoError(t, err)

			if tt.wantServers == 0 {
				assert.Nil(t, got.Node.MullvadDirect)
				return
			}

			require.NotNil(t, got.Node.MullvadDirect)
			assert.Len(t, got.Node.MullvadDirect.Servers, tt.wantServers)
			assert.Contains(t, got.Node.MullvadDirect.Devices, devKey)

			byCity := testMullvadByCity(t, got.Node.MullvadDirect)
			assert.Equal(t, 3, byCity["jp-tyo"].Location.Priority, "default_city decoded")
			assert.Less(t, byCity["jp-osa"].Location.Priority, 3)

			// /debug/config serves the whole Config as JSON.
			out, err := json.Marshal(got)
			require.NoError(t, err)

			raw := devKey.Raw32()
			assert.NotContains(t, string(out), hex.EncodeToString(raw[:]))
			assert.NotContains(t, string(out), "10.124.0.1")
		})
	}
}
