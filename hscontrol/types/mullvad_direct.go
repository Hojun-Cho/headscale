package types

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"maps"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/spf13/viper"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// MullvadDirectIDBase is the first [tailcfg.NodeID] of the synthetic Mullvad
// peers. Database IDs are autoincrement values that never get near it, so an
// ID at or above it always names a synthetic peer.
const MullvadDirectIDBase tailcfg.NodeID = 1 << 40

const (
	// mullvadMaxRelaysFile bounds the relay list read at startup; the real
	// list is about 300 KB.
	mullvadMaxRelaysFile = 4 << 20
	// mullvadMaxDevicesFile bounds the devices file.
	mullvadMaxDevicesFile = 1 << 20
	// mullvadMaxCities bounds the synthetic peers per viewer and keeps
	// their addresses inside 100.127.0.0/16.
	mullvadMaxCities = 1024
	// mullvadMaxName bounds the country and city names shown in pickers.
	mullvadMaxName = 64
	// mullvadPort is the port of every Mullvad WireGuard server.
	mullvadPort = 51820
	// mullvadDomain is the suffix Tailscale clients file Mullvad nodes under.
	mullvadDomain = "mullvad.ts.net"
)

// mullvadHostnameRE matches Mullvad WireGuard hostnames such as
// "jp-tyo-wg-001": country code, city label, then the server.
var mullvadHostnameRE = regexp.MustCompile(`^([a-z]{2})-([a-z0-9]+)-wg-[a-z0-9-]+$`)

var (
	mullvadDirectKeys = []string{"dns", "relays_path", "default_city", "devices", "devices_path"}
	mullvadDeviceKeys = []string{"name", "node_key", "ipv4", "ipv6", "mullvad_device"}
)

var errMullvadDirect = errors.New("node.mullvad_direct")

// IsMullvadDirectID reports whether id names a synthetic Mullvad peer.
func IsMullvadDirectID(id tailcfg.NodeID) bool {
	return id >= MullvadDirectIDBase
}

// MullvadDirectConfig is node.mullvad_direct as written in the config file.
type MullvadDirectConfig struct {
	// DNS is the resolver inside Mullvad's tunnel, 10.64.0.1.
	DNS string `mapstructure:"dns"`
	// RelaysPath is a copy of https://api.mullvad.net/www/relays/all/.
	RelaysPath string `mapstructure:"relays_path"`
	// DefaultCity, e.g. "jp-tyo", gets the highest priority, which makes
	// it the client's overall "best" exit.
	DefaultCity string                `mapstructure:"default_city"`
	Devices     []MullvadDeviceConfig `mapstructure:"devices"`
	// DevicesPath is a JSON array of devices, used instead of Devices so
	// a script can maintain the list (mullvad-add.sh).
	DevicesPath string `mapstructure:"devices_path"`
}

// MullvadDeviceConfig is one device whose node key is registered with Mullvad.
type MullvadDeviceConfig struct {
	Name    string `json:"name" mapstructure:"name"` // label only
	NodeKey string `json:"node_key" mapstructure:"node_key"`
	IPv4    string `json:"ipv4" mapstructure:"ipv4"`
	IPv6    string `json:"ipv6" mapstructure:"ipv6"`
	// MullvadDevice is the device's name on Mullvad's Devices page; label only.
	MullvadDevice string `json:"mullvad_device" mapstructure:"mullvad_device"`
}

// MullvadDirect is the parsed node.mullvad_direct.
type MullvadDirect struct {
	DNS     netip.Addr
	Servers []MullvadServer // one per city, ascending ID
	Devices map[key.NodePublic]MullvadDevice
}

// MullvadServer is the Mullvad server picked for one city. ID and StableID
// belong to the city, so a device keeps its choice when the server behind it
// changes at a refresh.
type MullvadServer struct {
	Hostname string
	ID       tailcfg.NodeID
	StableID tailcfg.StableNodeID
	Name     string // "<hostname>.mullvad.ts.net."
	Key      key.NodePublic
	Endpoint netip.AddrPort
	Addr4    netip.Prefix
	Addr6    netip.Prefix
	Location tailcfg.Location
}

// MullvadDevice holds the tunnel addresses Mullvad assigned to a device.
type MullvadDevice struct {
	Name string
	IPv4 netip.Addr
	IPv6 netip.Addr
}

// mullvadRelay is the part of a relay list entry that is used.
type mullvadRelay struct {
	Hostname    string          `json:"hostname"`
	CountryName string          `json:"country_name"`
	CityName    string          `json:"city_name"`
	Active      bool            `json:"active"`
	Owned       json.RawMessage `json:"owned"`
	Type        string          `json:"type"`
	Pubkey      string          `json:"pubkey"`
	IPv4AddrIn  string          `json:"ipv4_addr_in"`
}

// mullvadCandidate is a usable relay list entry.
type mullvadCandidate struct {
	hostname    string
	cityKey     string // "jp-tyo"
	countryCode string // "jp"
	cityLabel   string // "tyo"
	country     string
	city        string
	pubkey      string
	key         key.NodePublic
	addr        netip.Addr
	owned       bool
}

// mullvadDirect reads node.mullvad_direct and the relay list it names. It
// returns nil when the block is absent.
func mullvadDirect(prefix4, prefix6 *netip.Prefix, alloc IPAllocationStrategy) (*MullvadDirect, error) {
	block := viper.Get("node.mullvad_direct")
	if block == nil {
		// A key with nothing under it (say, every line commented out)
		// also reads as nil; that is a mistake, not "off".
		if node, ok := viper.Get("node").(map[string]any); ok {
			if _, present := node["mullvad_direct"]; present {
				return nil, fmt.Errorf("%w: the block is empty", errMullvadDirect)
			}
		}

		return nil, nil //nolint:nilnil // an absent block turns the feature off
	}

	err := checkMullvadKeys(block)
	if err != nil {
		return nil, err
	}

	var raw MullvadDirectConfig

	err = viper.UnmarshalKey("node.mullvad_direct", &raw)
	if err != nil {
		return nil, err
	}

	if raw.RelaysPath == "" {
		return nil, fmt.Errorf("%w: relays_path is empty", errMullvadDirect)
	}

	relays, err := readMullvadFile(util.AbsolutePathFromConfigPath(raw.RelaysPath), "relays_path", mullvadMaxRelaysFile)
	if err != nil {
		return nil, err
	}

	if raw.DevicesPath != "" {
		if len(raw.Devices) > 0 {
			return nil, fmt.Errorf("%w: set devices or devices_path, not both", errMullvadDirect)
		}

		raw.Devices, err = readMullvadDevices(util.AbsolutePathFromConfigPath(raw.DevicesPath))
		if err != nil {
			return nil, err
		}

		if len(raw.Devices) == 0 {
			return nil, fmt.Errorf("%w: devices_path: list at least one device", errMullvadDirect)
		}
	}

	return raw.Parse(relays, prefix4, prefix6, alloc)
}

// checkMullvadKeys rejects keys the block doesn't know, so a misspelt key
// fails configtest instead of quietly turning part of the feature off.
func checkMullvadKeys(block any) error {
	m, ok := block.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: want a mapping", errMullvadDirect)
	}

	for k := range m {
		if !slices.Contains(mullvadDirectKeys, k) {
			return fmt.Errorf("%w: unknown key %q", errMullvadDirect, k)
		}
	}

	devices, ok := m["devices"].([]any)
	if !ok {
		return nil
	}

	for i, d := range devices {
		dm, ok := d.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: devices[%d]: want a mapping", errMullvadDirect, i)
		}

		for k := range dm {
			if !slices.Contains(mullvadDeviceKeys, k) {
				return fmt.Errorf("%w: devices[%d]: unknown key %q", errMullvadDirect, i, k)
			}
		}
	}

	return nil
}

// readMullvadFile reads the file at path, named by its config key in errors.
func readMullvadFile(path, key string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errMullvadDirect, key, err)
	}
	defer f.Close()

	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errMullvadDirect, key, err)
	}

	if len(b) > limit {
		return nil, fmt.Errorf("%w: %s: larger than %d bytes", errMullvadDirect, key, limit)
	}

	return b, nil
}

// readMullvadDevices reads devices_path. Unknown fields are errors, so a
// misspelt key fails configtest.
func readMullvadDevices(path string) ([]MullvadDeviceConfig, error) {
	b, err := readMullvadFile(path, "devices_path", mullvadMaxDevicesFile)
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()

	var devices []MullvadDeviceConfig

	err = dec.Decode(&devices)
	if err != nil {
		return nil, fmt.Errorf("%w: devices_path: %w", errMullvadDirect, err)
	}

	// A stray bracket or a second array would silently drop devices.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: devices_path: data after the array", errMullvadDirect)
	}

	return devices, nil
}

// Parse validates c and builds one server per city from relays, the JSON of
// https://api.mullvad.net/www/relays/all/. Problems with the file as a whole
// or with c are errors. A relay entry that is inactive, not WireGuard or
// malformed is skipped, so one odd entry never blocks a refresh.
func (c MullvadDirectConfig) Parse(
	relays []byte,
	prefix4, prefix6 *netip.Prefix,
	alloc IPAllocationStrategy,
) (*MullvadDirect, error) {
	// The synthetic addresses sit at the top of the default prefixes, which
	// the sequential allocator never reaches; any other prefix or the
	// random allocator could hand a real node one of them.
	if alloc != IPAllocationStrategySequential {
		return nil, fmt.Errorf("%w: needs prefixes.allocation %q", errMullvadDirect, IPAllocationStrategySequential)
	}

	if prefix4 == nil || prefix6 == nil ||
		prefix4.Masked() != tsaddr.CGNATRange() || prefix6.Masked() != tsaddr.TailscaleULARange() {
		return nil, fmt.Errorf("%w: needs prefixes.v4 %s and prefixes.v6 %s",
			errMullvadDirect, tsaddr.CGNATRange(), tsaddr.TailscaleULARange())
	}

	// A resolver inside the tailnet range would be routed to a real peer.
	dns, err := netip.ParseAddr(c.DNS)
	if err != nil || !dns.Is4() || prefix4.Contains(dns) {
		return nil, fmt.Errorf("%w: dns %q: want an IPv4 address outside %s", errMullvadDirect, c.DNS, prefix4)
	}

	// Without one overall maximum, about 50 country main cities would tie
	// for the client's suggested exit.
	if c.DefaultCity == "" {
		return nil, fmt.Errorf("%w: default_city is required, e.g. \"jp-tyo\"", errMullvadDirect)
	}

	// A block without devices does nothing; most likely the list lost its
	// indentation and landed elsewhere under node:.
	if len(c.Devices) == 0 {
		return nil, fmt.Errorf("%w: devices: list at least one device", errMullvadDirect)
	}

	devices, err := parseMullvadDevices(c.Devices)
	if err != nil {
		return nil, err
	}

	servers, err := parseMullvadRelays(relays, c.DefaultCity)
	if err != nil {
		return nil, err
	}

	return &MullvadDirect{DNS: dns, Servers: servers, Devices: devices}, nil
}

func parseMullvadDevices(raw []MullvadDeviceConfig) (map[key.NodePublic]MullvadDevice, error) {
	devices := make(map[key.NodePublic]MullvadDevice, len(raw))
	seen := make(map[netip.Addr]bool, 2*len(raw))

	for i, d := range raw {
		if d.Name == "" {
			return nil, fmt.Errorf("%w: devices[%d]: name is empty", errMullvadDirect, i)
		}

		var k key.NodePublic

		err := k.UnmarshalText([]byte(d.NodeKey))
		if err != nil || k.IsZero() {
			return nil, fmt.Errorf("%w: device %q: node_key %q: want nodekey:<64 hex>", errMullvadDirect, d.Name, d.NodeKey)
		}

		if _, dup := devices[k]; dup {
			return nil, fmt.Errorf("%w: device %q: duplicate node_key", errMullvadDirect, d.Name)
		}

		// A wrong family would panic the client's source rewrite.
		v4, err := parseMullvadAddr(d.IPv4)
		if err != nil || !v4.Is4() {
			return nil, fmt.Errorf("%w: device %q: ipv4 %q: want one IPv4 address", errMullvadDirect, d.Name, d.IPv4)
		}

		v6, err := parseMullvadAddr(d.IPv6)
		if err != nil || !v6.Is6() || v6.Is4In6() || v6.Zone() != "" {
			return nil, fmt.Errorf("%w: device %q: ipv6 %q: want one IPv6 address", errMullvadDirect, d.Name, d.IPv6)
		}

		if seen[v4] || seen[v6] {
			return nil, fmt.Errorf("%w: device %q: address already used by another device", errMullvadDirect, d.Name)
		}

		seen[v4], seen[v6] = true, true
		devices[k] = MullvadDevice{Name: d.Name, IPv4: v4, IPv6: v6}
	}

	return devices, nil
}

// parseMullvadAddr accepts an address or the single-address CIDR form
// Mullvad's API returns ("10.124.0.1/32").
func parseMullvadAddr(s string) (netip.Addr, error) {
	if !strings.Contains(s, "/") {
		return netip.ParseAddr(s)
	}

	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Addr{}, err
	}

	if !p.IsSingleIP() {
		return netip.Addr{}, fmt.Errorf("%w: %q is not a single address", errMullvadDirect, s)
	}

	return p.Addr(), nil
}

func parseMullvadRelays(relays []byte, defaultCity string) ([]MullvadServer, error) {
	var entries []json.RawMessage

	err := json.Unmarshal(relays, &entries)
	if err != nil {
		return nil, fmt.Errorf("%w: the relay list is not a JSON array: %w", errMullvadDirect, err)
	}

	var cands []mullvadCandidate

	for _, e := range entries {
		if c, ok := mullvadCandidateFrom(e); ok {
			cands = append(cands, c)
		}
	}

	// Sort on every field first, so the result doesn't depend on the
	// list's order; then keep the first entry for each hostname, key and
	// address.
	slices.SortFunc(cands, func(a, b mullvadCandidate) int {
		return cmp.Or(
			cmp.Compare(a.hostname, b.hostname),
			cmp.Compare(a.pubkey, b.pubkey),
			a.addr.Compare(b.addr),
			ownedFirst(a.owned, b.owned),
			cmp.Compare(a.country, b.country),
			cmp.Compare(a.city, b.city),
		)
	})

	type city struct {
		pick  mullvadCandidate
		count int
	}

	var (
		cities   = make(map[string]*city)
		seenHost = make(map[string]bool)
		seenKey  = make(map[key.NodePublic]bool)
		seenAddr = make(map[netip.Addr]bool)
	)

	for _, c := range cands {
		if seenHost[c.hostname] || seenKey[c.key] || seenAddr[c.addr] {
			continue
		}

		seenHost[c.hostname], seenKey[c.key], seenAddr[c.addr] = true, true, true

		// One server per city: the first Mullvad-owned one, else the
		// first by hostname.
		ct, ok := cities[c.cityKey]
		if !ok {
			cities[c.cityKey] = &city{pick: c, count: 1}
			continue
		}

		ct.count++
		if c.owned && !ct.pick.owned {
			ct.pick = c
		}
	}

	// IDs belong to cities. On a hash collision the later city key is
	// dropped, before anything below looks at the cities.
	ids := make(map[string]tailcfg.NodeID, len(cities))
	seenID := make(map[tailcfg.NodeID]bool, len(cities))

	for _, k := range slices.Sorted(maps.Keys(cities)) {
		h := fnv.New32a()
		h.Write([]byte(k))

		id := MullvadDirectIDBase + tailcfg.NodeID(h.Sum32())
		if seenID[id] {
			delete(cities, k)
			continue
		}

		seenID[id] = true
		ids[k] = id
	}

	switch {
	case len(cities) == 0:
		return nil, fmt.Errorf("%w: the relay list has no active WireGuard server", errMullvadDirect)
	case len(cities) > mullvadMaxCities:
		return nil, fmt.Errorf("%w: the relay list has %d cities, more than %d", errMullvadDirect, len(cities), mullvadMaxCities)
	case cities[defaultCity] == nil:
		return nil, fmt.Errorf("%w: default_city %q is not in the relay list", errMullvadDirect, defaultCity)
	}

	cityKeys := slices.Sorted(maps.Keys(cities))

	// A city label used in several countries gets the country prefix,
	// because clients key cities by CityCode across the whole tailnet.
	labelCountries := make(map[string]map[string]bool)
	// Each country's main city is the one with the most servers; a tie
	// goes to the smaller city key.
	mainCity := make(map[string]string)

	for _, k := range cityKeys {
		p := cities[k].pick
		if labelCountries[p.cityLabel] == nil {
			labelCountries[p.cityLabel] = make(map[string]bool)
		}

		labelCountries[p.cityLabel][p.countryCode] = true

		cur, ok := mainCity[p.countryCode]
		if !ok || cities[k].count > cities[cur].count {
			mainCity[p.countryCode] = k
		}
	}

	servers := make([]MullvadServer, 0, len(cities))

	for _, k := range cityKeys {
		p := cities[k].pick

		cityCode := strings.ToUpper(p.cityLabel)
		if len(labelCountries[p.cityLabel]) > 1 {
			cityCode = strings.ToUpper(k)
		}

		// Clients pick the highest Priority per city, per country and
		// overall, so each level gets exactly one maximum.
		priority := 1
		if mainCity[p.countryCode] == k {
			priority = 2
		}

		if k == defaultCity {
			priority = 3
		}

		servers = append(servers, MullvadServer{
			Hostname: p.hostname,
			ID:       ids[k],
			StableID: tailcfg.StableNodeID("mullvad-" + k),
			Name:     p.hostname + "." + mullvadDomain + ".",
			Key:      p.key,
			Endpoint: netip.AddrPortFrom(p.addr, mullvadPort),
			// No Latitude/Longitude: headscale's DERP region has no
			// coordinates, so clients would measure distances from (0,0).
			Location: tailcfg.Location{
				Country:     p.country,
				CountryCode: strings.ToUpper(p.countryCode),
				City:        p.city,
				CityCode:    cityCode,
				Priority:    priority,
			},
		})
	}

	slices.SortFunc(servers, func(a, b MullvadServer) int { return cmp.Compare(a.ID, b.ID) })

	// 100.127.0.1 up and fd7a:115c:a1e0:ffff::1 up. They may change at a
	// refresh; clients remember the chosen exit by StableID.
	for i := range servers {
		v4 := netip.AddrFrom4([4]byte{100, 127, byte(i / 254), byte(i%254 + 1)})
		v6 := netip.MustParseAddr("fd7a:115c:a1e0:ffff::").As16()
		binary.BigEndian.PutUint16(v6[14:], uint16(i+1)) //nolint:gosec // i < mullvadMaxCities

		servers[i].Addr4 = netip.PrefixFrom(v4, v4.BitLen())
		servers[i].Addr6 = netip.PrefixFrom(netip.AddrFrom16(v6), 128)
	}

	return servers, nil
}

func ownedFirst(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	}

	return 1
}

// mullvadCandidateFrom decodes one relay list entry and reports whether it
// is a usable WireGuard server.
func mullvadCandidateFrom(raw json.RawMessage) (mullvadCandidate, bool) {
	var r mullvadRelay

	err := json.Unmarshal(raw, &r)
	if err != nil || !r.Active || r.Type != "wireguard" ||
		!mullvadName(r.CountryName) || !mullvadName(r.CityName) {
		return mullvadCandidate{}, false
	}

	m := mullvadHostnameRE.FindStringSubmatch(r.Hostname)
	if m == nil || ValidateGivenName(r.Hostname, mullvadDomain) != nil {
		return mullvadCandidate{}, false
	}

	// Never key.NodePublicFromRaw32: it panics on a wrong length.
	pub, err := base64.StdEncoding.DecodeString(r.Pubkey)
	if err != nil || len(pub) != 32 || !slices.ContainsFunc(pub, func(b byte) bool { return b != 0 }) {
		return mullvadCandidate{}, false
	}

	var k key.NodePublic

	err = k.UnmarshalText([]byte("nodekey:" + hex.EncodeToString(pub)))
	if err != nil {
		return mullvadCandidate{}, false
	}

	addr, err := netip.ParseAddr(r.IPv4AddrIn)
	if err != nil || !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsPrivate() || tsaddr.CGNATRange().Contains(addr) {
		return mullvadCandidate{}, false
	}

	return mullvadCandidate{
		hostname:    r.Hostname,
		cityKey:     m[1] + "-" + m[2],
		countryCode: m[1],
		cityLabel:   m[2],
		country:     r.CountryName,
		city:        r.CityName,
		pubkey:      r.Pubkey,
		key:         k,
		addr:        addr,
		owned:       string(bytes.TrimSpace(r.Owned)) == "true",
	}, true
}

// mullvadName reports whether a country or city name from the relay list is
// fit to show in a picker: short, and free of control characters,
// bidirectional controls and U+FFFD (encoding/json's replacement for
// invalid UTF-8).
func mullvadName(s string) bool {
	if s == "" || len(s) > mullvadMaxName {
		return false
	}

	return !strings.ContainsFunc(s, func(r rune) bool {
		return r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r)
	})
}
