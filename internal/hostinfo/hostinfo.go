// Package hostinfo reports the health of the machine the node runs on.
//
// This exists so that the answer to "why has it gone slow" does not require
// ssh. A resolver that stops answering because the card filled up, or because
// the power supply sags and the processor throttles itself to a crawl, gives
// exactly the same symptom as a network fault — and a household will look at
// the network for an hour before they look at the disk.
//
// Everything here is read from the kernel's own files. Nothing is estimated:
// if a machine does not publish its temperature, this says so rather than
// inventing one, and the panel shows nothing rather than a plausible number.
package hostinfo

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Snapshot is the state of the machine at one moment.
type Snapshot struct {
	// Model is what the machine calls itself, when it says.
	Model string `json:"model,omitempty"`

	// UptimeSeconds is how long it has been running.
	UptimeSeconds int64 `json:"uptime_seconds"`

	CPU    CPU     `json:"cpu"`
	Memory Memory  `json:"memory"`
	Swap   *Memory `json:"swap,omitempty"`
	Disks  []Disk  `json:"disks"`

	// TemperatureC is nil on machines that do not publish one. A missing
	// reading is reported as missing rather than as zero, which would look
	// like a suspiciously cold machine.
	TemperatureC *float64 `json:"temperature_c,omitempty"`

	// Throttling is what the board says has gone wrong with its power or
	// heat. Empty on hardware that does not report it.
	Throttling []string `json:"throttling,omitempty"`
}

// CPU is processor use.
type CPU struct {
	// BusyPercent is the share of time not spent idle, across all cores,
	// measured between the two most recent readings.
	BusyPercent float64 `json:"busy_percent"`

	// PerCorePercent is the same figure for each core, so one pegged core is
	// distinguishable from an evenly busy machine.
	PerCorePercent []float64 `json:"per_core_percent,omitempty"`

	Cores int `json:"cores"`

	// Load is the kernel's own one, five and fifteen minute averages.
	Load [3]float64 `json:"load"`
}

// Memory is a total and what is in use.
type Memory struct {
	TotalBytes int64 `json:"total_bytes"`
	UsedBytes  int64 `json:"used_bytes"`
}

// UsedPercent is what a person actually looks at.
func (m Memory) UsedPercent() float64 {
	if m.TotalBytes <= 0 {
		return 0
	}

	return float64(m.UsedBytes) / float64(m.TotalBytes) * 100
}

// Disk is one filesystem worth showing.
type Disk struct {
	// Path is the mount point.
	Path string `json:"path"`

	// Label says what lives there in the words of someone who did not install
	// it — "the system", "SedDNS data".
	Label string `json:"label"`

	TotalBytes int64 `json:"total_bytes"`
	UsedBytes  int64 `json:"used_bytes"`
}

// UsedPercent is the share in use.
func (d Disk) UsedPercent() float64 {
	if d.TotalBytes <= 0 {
		return 0
	}

	return float64(d.UsedBytes) / float64(d.TotalBytes) * 100
}

// StatFS reports the size and free space of a filesystem.
//
// Injectable so the rules above can be exercised without needing a disk of a
// particular size to hand.
type StatFS func(path string) (totalBytes, freeBytes int64, err error)

// Reader takes snapshots.
//
// It holds the previous processor reading, because use is a difference between
// two moments and a single reading can only ever give the average since boot —
// which on a machine up for a month is a flat and useless number.
type Reader struct {
	// root is the filesystem the kernel's files are read from, so tests can
	// supply a machine rather than describe one.
	root string

	// dataPath is the directory the node stores its database in, which is the
	// filesystem worth watching most closely.
	dataPath string

	statfs StatFS

	mu   sync.Mutex
	prev cpuSample
}

// New creates a reader for this machine.
func New(dataPath string) *Reader {
	return &Reader{root: "/", dataPath: dataPath, statfs: statFS}
}

// WithStatFS swaps the filesystem measurement.
func (r *Reader) WithStatFS(fn StatFS) *Reader {
	r.statfs = fn

	return r
}

func (r *Reader) path(rest ...string) string {
	return filepath.Join(append([]string{r.root}, rest...)...)
}

// Read takes a snapshot.
//
// Every part is optional: a machine missing any one of these files is unusual
// but not a reason to fail the whole screen, so each failure leaves its own
// field empty and the rest is still reported.
func (r *Reader) Read() Snapshot {
	snap := Snapshot{
		Model:         r.model(),
		UptimeSeconds: r.uptime(),
		CPU:           r.cpu(),
		Memory:        Memory{},
		Disks:         r.disks(),
		TemperatureC:  r.temperature(),
		Throttling:    r.throttling(),
	}

	snap.Memory, snap.Swap = r.memory()

	return snap
}

// model reads what the board calls itself.
//
// The device tree is where a Raspberry Pi says so; the DMI table is where a
// PC or a virtual machine does. Neither exists everywhere.
func (r *Reader) model() string {
	for _, candidate := range []string{
		"proc/device-tree/model",
		"sys/devices/virtual/dmi/id/product_name",
	} {
		raw, err := os.ReadFile(r.path(candidate))
		if err != nil {
			continue
		}

		// The device tree string is null-terminated.
		if name := strings.TrimSpace(strings.Trim(string(raw), "\x00")); name != "" {
			return name
		}
	}

	return ""
}

func (r *Reader) uptime() int64 {
	raw, err := os.ReadFile(r.path("proc/uptime"))
	if err != nil {
		return 0
	}

	seconds, err := strconv.ParseFloat(strings.Fields(string(raw))[0], 64)
	if err != nil {
		return 0
	}

	return int64(seconds)
}

// cpuSample is one reading of the processor counters.
type cpuSample struct {
	taken time.Time
	total []cpuTimes
}

type cpuTimes struct {
	busy, idle uint64
}

// cpu measures processor use between this reading and the previous one.
//
// On the first call there is no previous reading, so it takes two a short
// distance apart rather than reporting the since-boot average, which would be
// wrong in a way nobody could see.
func (r *Reader) cpu() CPU {
	out := CPU{Load: r.loadavg()}

	sample, ok := r.readCPU()
	if !ok {
		return out
	}

	r.mu.Lock()
	prev := r.prev
	r.mu.Unlock()

	if len(prev.total) != len(sample.total) {
		time.Sleep(120 * time.Millisecond)

		second, secondOK := r.readCPU()
		if !secondOK {
			return out
		}

		prev, sample = sample, second
	}

	r.mu.Lock()
	r.prev = sample
	r.mu.Unlock()

	if len(sample.total) == 0 {
		return out
	}

	out.Cores = len(sample.total) - 1
	out.BusyPercent = busyBetween(prev.total[0], sample.total[0])

	for i := 1; i < len(sample.total); i++ {
		out.PerCorePercent = append(out.PerCorePercent, busyBetween(prev.total[i], sample.total[i]))
	}

	return out
}

// busyBetween is the share of elapsed processor time that was not idle.
func busyBetween(before, after cpuTimes) float64 {
	busy := int64(after.busy) - int64(before.busy)
	idle := int64(after.idle) - int64(before.idle)
	total := busy + idle

	// Counters can go backwards across a suspend, and a zero interval means
	// two readings landed in the same tick. Neither is worth a wrong number.
	if total <= 0 || busy < 0 {
		return 0
	}

	return float64(busy) / float64(total) * 100
}

// readCPU parses /proc/stat. The first entry is the whole machine, the rest
// are individual cores, in order.
func (r *Reader) readCPU() (cpuSample, bool) {
	file, err := os.Open(r.path("proc/stat"))
	if err != nil {
		return cpuSample{}, false
	}
	defer func() { _ = file.Close() }()

	sample := cpuSample{taken: time.Now()}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}

		var times cpuTimes
		for i, field := range fields[1:] {
			value, parseErr := strconv.ParseUint(field, 10, 64)
			if parseErr != nil {
				break
			}

			// Fields 4 and 5 are idle and iowait; everything else is work.
			if i == 3 || i == 4 {
				times.idle += value

				continue
			}

			times.busy += value
		}

		sample.total = append(sample.total, times)
	}

	if len(sample.total) == 0 {
		return cpuSample{}, false
	}

	return sample, true
}

func (r *Reader) loadavg() [3]float64 {
	var load [3]float64

	raw, err := os.ReadFile(r.path("proc/loadavg"))
	if err != nil {
		return load
	}

	fields := strings.Fields(string(raw))
	for i := 0; i < 3 && i < len(fields); i++ {
		load[i], _ = strconv.ParseFloat(fields[i], 64)
	}

	return load
}

// memory reads what is in use.
//
// Used is total minus available, not total minus free. Linux fills spare
// memory with cache and gives it back on demand, so "free" on a healthy
// machine is always near zero and reporting it would have every household
// believing they were out of memory.
func (r *Reader) memory() (Memory, *Memory) {
	file, err := os.Open(r.path("proc/meminfo"))
	if err != nil {
		return Memory{}, nil
	}
	defer func() { _ = file.Close() }()

	values := map[string]int64{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, rest, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}

		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}

		kb, parseErr := strconv.ParseInt(fields[0], 10, 64)
		if parseErr != nil {
			continue
		}

		values[key] = kb * 1024
	}

	ram := Memory{TotalBytes: values["MemTotal"]}
	ram.UsedBytes = ram.TotalBytes - values["MemAvailable"]
	if ram.UsedBytes < 0 {
		ram.UsedBytes = 0
	}

	total := values["SwapTotal"]
	if total <= 0 {
		return ram, nil
	}

	return ram, &Memory{TotalBytes: total, UsedBytes: total - values["SwapFree"]}
}

// disks measures the filesystems worth watching.
//
// Only two: the one the system is on and the one the node's own data is on.
// Listing every mount would bury both under loop devices and tmpfs.
func (r *Reader) disks() []Disk {
	seen := map[string]bool{}

	var out []Disk
	for _, candidate := range []struct{ path, label string }{
		{r.dataPath, "SedDNS data"},
		{r.root, "System"},
	} {
		if candidate.path == "" {
			continue
		}

		total, free, err := r.statfs(candidate.path)
		if err != nil || total <= 0 {
			continue
		}

		// The data directory is usually on the system filesystem; showing the
		// same disk twice under two names would read as two disks.
		key := strconv.FormatInt(total, 10) + ":" + strconv.FormatInt(free, 10)
		if seen[key] {
			continue
		}
		seen[key] = true

		out = append(out, Disk{
			Path:       candidate.path,
			Label:      candidate.label,
			TotalBytes: total,
			UsedBytes:  total - free,
		})
	}

	return out
}

// temperature reads the warmest thermal zone.
//
// The warmest rather than the first: a board publishes several, and the one
// that matters is whichever is closest to the limit.
func (r *Reader) temperature() *float64 {
	zones, err := filepath.Glob(r.path("sys/class/thermal/thermal_zone*/temp"))
	if err != nil || len(zones) == 0 {
		return nil
	}

	var warmest float64
	found := false

	for _, zone := range zones {
		raw, readErr := os.ReadFile(zone)
		if readErr != nil {
			continue
		}

		milli, parseErr := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
		if parseErr != nil {
			continue
		}

		celsius := milli / 1000

		// A zone that reads absurdly is a driver that does not work, not a
		// machine on fire.
		if celsius <= 0 || celsius > 150 {
			continue
		}

		if !found || celsius > warmest {
			warmest, found = celsius, true
		}
	}

	if !found {
		return nil
	}

	return &warmest
}

// throttleFlags are what a Raspberry Pi reports about its own power and heat.
//
// Worth surfacing because an undervolted Pi does not fail: it quietly runs at
// a fraction of its speed, and the household experiences that as "the internet
// is slow" with nothing in any log to explain it. The usual cause is a phone
// charger being used as a power supply.
var throttleFlags = []struct {
	bit  uint64
	text string
}{
	{0, "not enough power right now — check the power supply and cable"},
	{1, "running slower because it is too hot right now"},
	{3, "too hot right now"},
	{16, "has not had enough power at some point since it started"},
	{19, "has been too hot at some point since it started"},
}

// throttling reads the board's own report.
func (r *Reader) throttling() []string {
	raw, err := os.ReadFile(r.path("sys/devices/platform/soc/soc:firmware/get_throttled"))
	if err != nil {
		return nil
	}

	text := strings.TrimSpace(string(raw))
	text = strings.TrimPrefix(text, "0x")

	value, err := strconv.ParseUint(text, 16, 64)
	if err != nil || value == 0 {
		return nil
	}

	var out []string
	for _, flag := range throttleFlags {
		if value&(1<<flag.bit) != 0 {
			out = append(out, flag.text)
		}
	}

	return out
}
