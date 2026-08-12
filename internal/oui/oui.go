// Package oui turns a hardware address into a manufacturer name.
//
// The IEEE registry is embedded in full — about 40,000 assignments, 338 KB
// compressed — rather than a curated subset, because a device list that says
// "Apple" for some devices and a bare address for others is worse than useless
// for identifying what is on your network.
//
// It is decompressed on first use and held as two parallel sorted slices, the
// same shape as the filter index and for the same reason: no per-entry map
// overhead on a machine that also has to hold a blocklist.
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// registry holds the compacted IEEE assignments, one "PREFIX\tvendor" line per
// entry, sorted by prefix.
//
//go:embed data/oui.tsv.gz
var registry []byte

var (
	once     sync.Once
	prefixes []uint32
	vendors  []string
	loadErr  error

	// extra holds assignments loaded from disk, which take precedence so an
	// operator can correct or extend the embedded copy without a new release.
	extraMu sync.RWMutex
	extra   map[uint32]string
)

// Lookup returns the manufacturer for a hardware address.
//
// found is false for an address that is not in the registry, and for a
// randomised one — see Randomised.
func Lookup(mac string) (vendor string, found bool) {
	prefix, ok := parsePrefix(mac)
	if !ok {
		return "", false
	}

	// A randomised address belongs to nobody: the registry would either miss
	// it or, worse, report whichever company happens to own that range.
	if Randomised(mac) {
		return "", false
	}

	extraMu.RLock()
	if name, hit := extra[prefix]; hit {
		extraMu.RUnlock()

		return name, true
	}
	extraMu.RUnlock()

	load()
	if loadErr != nil {
		return "", false
	}

	i := sort.Search(len(prefixes), func(i int) bool { return prefixes[i] >= prefix })
	if i < len(prefixes) && prefixes[i] == prefix {
		return vendors[i], true
	}

	return "", false
}

// Randomised reports whether an address is locally administered, which is what
// a phone doing MAC randomisation uses.
//
// This matters for identity, not for cosmetics: such an address changes per
// network and often per join, so it cannot be used to recognise a device over
// time, and the panel must not offer it as a stable handle.
func Randomised(mac string) bool {
	first, ok := firstOctet(mac)
	if !ok {
		return false
	}

	// Bit 1 of the first octet is the locally-administered flag.
	return first&0x02 != 0
}

// Multicast reports whether an address is a group address, which should never
// appear as a client.
func Multicast(mac string) bool {
	first, ok := firstOctet(mac)
	if !ok {
		return false
	}

	return first&0x01 != 0
}

// Describe returns a short human label for an address: the vendor when it is
// known, and an explicit note when the address is randomised.
func Describe(mac string) string {
	if mac == "" {
		return ""
	}

	if Randomised(mac) {
		return "randomised address"
	}

	if vendor, found := Lookup(mac); found {
		return vendor
	}

	return ""
}

// LoadFile merges additional assignments from an IEEE-style CSV or a simple
// "PREFIX<tab>vendor" file, so a deployment can stay current between releases.
func LoadFile(path string) (added int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening oui file: %w", err)
	}
	defer func() { _ = f.Close() }()

	parsed := map[uint32]string{}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Registry,") {
			continue
		}

		var rawPrefix, name string
		switch {
		case strings.Contains(line, "\t"):
			rawPrefix, name, _ = strings.Cut(line, "\t")
		case strings.Count(line, ",") >= 2:
			// IEEE csv: Registry,Assignment,Organization Name,...
			fields := strings.SplitN(line, ",", 4)
			rawPrefix, name = fields[1], strings.Trim(fields[2], `"`)
		default:
			continue
		}

		prefix, ok := parsePrefix(strings.TrimSpace(rawPrefix))
		if !ok {
			continue
		}

		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		parsed[prefix] = name
	}

	if err = scanner.Err(); err != nil {
		return 0, fmt.Errorf("reading oui file: %w", err)
	}

	extraMu.Lock()
	extra = parsed
	extraMu.Unlock()

	return len(parsed), nil
}

// Len reports how many assignments are loaded, for the panel.
func Len() int {
	load()

	extraMu.RLock()
	defer extraMu.RUnlock()

	return len(prefixes) + len(extra)
}

func load() {
	once.Do(func() {
		reader, err := gzip.NewReader(bytes.NewReader(registry))
		if err != nil {
			loadErr = fmt.Errorf("opening embedded registry: %w", err)

			return
		}
		defer func() { _ = reader.Close() }()

		blob, err := io.ReadAll(reader)
		if err != nil {
			loadErr = fmt.Errorf("reading embedded registry: %w", err)

			return
		}

		// Sized up front: the registry's length is known and growing these by
		// append would double-allocate a megabyte on a Raspberry Pi.
		prefixes = make([]uint32, 0, 40_000)
		vendors = make([]string, 0, 40_000)

		for line := range strings.Lines(string(blob)) {
			raw, name, ok := strings.Cut(strings.TrimSuffix(line, "\n"), "\t")
			if !ok {
				continue
			}

			prefix, valid := parsePrefix(raw)
			if !valid {
				continue
			}

			prefixes = append(prefixes, prefix)
			vendors = append(vendors, name)
		}

		// The data ships sorted; sorting again costs little and means a
		// hand-edited file cannot silently break the binary search.
		if !sort.SliceIsSorted(prefixes, func(i, j int) bool { return prefixes[i] < prefixes[j] }) {
			sort.Sort(&byPrefix{prefixes: prefixes, vendors: vendors})
		}
	})
}

type byPrefix struct {
	prefixes []uint32
	vendors  []string
}

func (b *byPrefix) Len() int           { return len(b.prefixes) }
func (b *byPrefix) Less(i, j int) bool { return b.prefixes[i] < b.prefixes[j] }
func (b *byPrefix) Swap(i, j int) {
	b.prefixes[i], b.prefixes[j] = b.prefixes[j], b.prefixes[i]
	b.vendors[i], b.vendors[j] = b.vendors[j], b.vendors[i]
}

// parsePrefix reads the first three octets of an address, accepting the
// separators the world actually uses.
func parsePrefix(mac string) (prefix uint32, ok bool) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', '.', ' ':
			return -1
		default:
			return r
		}
	}, strings.TrimSpace(mac))

	if len(cleaned) < 6 {
		return 0, false
	}

	value, err := strconv.ParseUint(cleaned[:6], 16, 32)
	if err != nil {
		return 0, false
	}

	return uint32(value), true
}

func firstOctet(mac string) (octet byte, ok bool) {
	prefix, ok := parsePrefix(mac)
	if !ok {
		return 0, false
	}

	return byte(prefix >> 16), true
}
