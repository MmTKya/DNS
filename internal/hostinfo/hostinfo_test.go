package hostinfo

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// machine writes a fake /proc and /sys so the parsing can be exercised against
// a machine of a known shape rather than whichever one the tests run on.
func machine(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for name, content := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return root
}

func TestUsedMemoryIsWhatIsNotAvailableRatherThanWhatIsNotFree(t *testing.T) {
	// A healthy Linux machine has almost no free memory because the kernel
	// fills the spare with cache. Reporting free would put every household at
	// 97% used and looking for a problem that is not there.
	root := machine(t, map[string]string{
		"proc/meminfo": "MemTotal:       8000000 kB\nMemFree:         200000 kB\nMemAvailable:   6000000 kB\n",
	})

	ram, swap := (&Reader{root: root}).memory()

	if ram.TotalBytes != 8000000*1024 {
		t.Fatalf("total = %d", ram.TotalBytes)
	}
	if want := int64(2000000 * 1024); ram.UsedBytes != want {
		t.Fatalf("used = %d, want %d (total minus available)", ram.UsedBytes, want)
	}
	if got := ram.UsedPercent(); got < 24 || got > 26 {
		t.Fatalf("used = %.1f%%, want about 25", got)
	}
	if swap != nil {
		t.Fatal("a machine with no swap should report none, not an empty one")
	}
}

func TestSwapIsReportedWhenThereIsSome(t *testing.T) {
	root := machine(t, map[string]string{
		"proc/meminfo": "MemTotal: 1000 kB\nMemAvailable: 500 kB\nSwapTotal: 2048 kB\nSwapFree: 1024 kB\n",
	})

	_, swap := (&Reader{root: root}).memory()

	if swap == nil {
		t.Fatal("swap was not reported")
	}
	if swap.UsedBytes != 1024*1024 {
		t.Fatalf("swap used = %d", swap.UsedBytes)
	}
}

func TestProcessorUseIsMeasuredBetweenTwoReadings(t *testing.T) {
	// A single reading can only give the average since boot, which on a
	// machine up for a month is flat and tells nobody anything.
	root := machine(t, map[string]string{
		// user nice system idle iowait ...
		"proc/stat":    "cpu  100 0 0 100 0 0 0\ncpu0 100 0 0 100 0 0 0\n",
		"proc/loadavg": "0.50 0.40 0.30 1/200 1234\n",
	})

	r := &Reader{root: root}
	if _, ok := r.readCPU(); !ok {
		t.Fatal("first reading failed")
	}

	// Between the readings: 100 ticks of work and 100 of idle, so half busy.
	before := cpuTimes{busy: 100, idle: 100}
	after := cpuTimes{busy: 200, idle: 200}

	if got := busyBetween(before, after); got < 49 || got > 51 {
		t.Fatalf("busy = %.1f%%, want about 50", got)
	}

	got := r.cpu()
	if got.Load != [3]float64{0.50, 0.40, 0.30} {
		t.Fatalf("load = %v", got.Load)
	}
	if got.Cores != 1 {
		t.Fatalf("cores = %d, want 1 (the first line is the whole machine)", got.Cores)
	}
}

func TestCountersGoingBackwardsDoNotProduceANumber(t *testing.T) {
	// They do this across a suspend, and a negative interval rendered as a
	// percentage is worse than showing nothing.
	if got := busyBetween(cpuTimes{busy: 500, idle: 500}, cpuTimes{busy: 100, idle: 100}); got != 0 {
		t.Fatalf("busy = %.1f, want 0", got)
	}

	// Two readings inside the same tick.
	if got := busyBetween(cpuTimes{busy: 100, idle: 100}, cpuTimes{busy: 100, idle: 100}); got != 0 {
		t.Fatalf("busy = %.1f, want 0", got)
	}
}

func TestAMachineWithNoTemperatureReportsNoneRatherThanZero(t *testing.T) {
	root := machine(t, map[string]string{"proc/uptime": "100.0 100.0\n"})

	if got := (&Reader{root: root}).temperature(); got != nil {
		t.Fatalf("temperature = %v, want nothing at all", *got)
	}
}

func TestTheWarmestZoneIsTheOneReported(t *testing.T) {
	// A board publishes several; the one that matters is whichever is closest
	// to its limit.
	root := machine(t, map[string]string{
		"sys/class/thermal/thermal_zone0/temp": "42000\n",
		"sys/class/thermal/thermal_zone1/temp": "58500\n",
		// A driver that does not work, rather than a machine on fire.
		"sys/class/thermal/thermal_zone2/temp": "9999000\n",
	})

	got := (&Reader{root: root}).temperature()
	if got == nil {
		t.Fatal("no temperature was reported")
	}
	if *got != 58.5 {
		t.Fatalf("temperature = %.1f, want 58.5", *got)
	}
}

func TestUnderpoweringIsReportedInWordsAPersonCanActon(t *testing.T) {
	// An undervolted Pi does not fail — it runs at a fraction of its speed,
	// which the household experiences as "the internet is slow" with nothing
	// in any log to explain it.
	root := machine(t, map[string]string{
		"sys/devices/platform/soc/soc:firmware/get_throttled": "0x50005\n",
	})

	got := (&Reader{root: root}).throttling()

	if len(got) == 0 {
		t.Fatal("nothing was reported for a board saying it is underpowered")
	}

	var mentionsPower bool
	for _, line := range got {
		if len(line) > 0 && line[0] >= 'a' && line[0] <= 'z' {
			mentionsPower = mentionsPower || contains(line, "power")
		}
	}
	if !mentionsPower {
		t.Fatalf("no mention of power in %v", got)
	}
}

func TestAHealthyBoardReportsNothing(t *testing.T) {
	root := machine(t, map[string]string{
		"sys/devices/platform/soc/soc:firmware/get_throttled": "0x0\n",
	})

	if got := (&Reader{root: root}).throttling(); got != nil {
		t.Fatalf("throttling = %v, want nothing", got)
	}
}

func TestTheSameDiskIsNotShownTwiceUnderTwoNames(t *testing.T) {
	// The data directory is usually on the system filesystem, and listing both
	// would read as two disks with a suspiciously identical amount free.
	r := &Reader{
		root:     "/",
		dataPath: "/var/lib/seddns",
		statfs: func(string) (int64, int64, error) {
			return 60_000_000_000, 40_000_000_000, nil
		},
	}

	disks := r.disks()

	if len(disks) != 1 {
		t.Fatalf("got %d disks, want 1", len(disks))
	}
	if got := disks[0].UsedPercent(); got < 33 || got > 34 {
		t.Fatalf("used = %.1f%%, want about 33", got)
	}
}

func TestSeparateDisksAreBothShown(t *testing.T) {
	r := &Reader{
		root:     "/",
		dataPath: "/mnt/ssd/seddns",
		statfs: func(path string) (int64, int64, error) {
			if path == "/" {
				return 30_000_000_000, 10_000_000_000, nil
			}

			return 500_000_000_000, 400_000_000_000, nil
		},
	}

	if disks := r.disks(); len(disks) != 2 {
		t.Fatalf("got %d disks, want 2", len(disks))
	}
}

func TestAFilesystemThatCannotBeMeasuredIsSkippedRatherThanShownAsEmpty(t *testing.T) {
	r := &Reader{
		root:     "/",
		dataPath: "/gone",
		statfs:   func(string) (int64, int64, error) { return 0, 0, errors.New("no such file") },
	}

	if disks := r.disks(); len(disks) != 0 {
		t.Fatalf("got %v, want nothing", disks)
	}
}

func TestAMissingFileLeavesOneFieldEmptyRatherThanFailingTheScreen(t *testing.T) {
	// A machine without one of these files is unusual, but the rest of the
	// screen is still worth showing.
	root := machine(t, map[string]string{
		"proc/uptime": "86400.00 86400.00\n",
	})

	snap := (&Reader{root: root, statfs: func(string) (int64, int64, error) {
		return 0, 0, errors.New("nothing here")
	}}).Read()

	if snap.UptimeSeconds != 86400 {
		t.Fatalf("uptime = %d", snap.UptimeSeconds)
	}
	if snap.Memory.TotalBytes != 0 || snap.TemperatureC != nil || len(snap.Disks) != 0 {
		t.Fatal("a missing file should leave its own field empty")
	}
}

func TestTheModelIsReadFromWhicheverPlaceTheMachinePublishesIt(t *testing.T) {
	pi := machine(t, map[string]string{"proc/device-tree/model": "Raspberry Pi 5 Model B Rev 1.0\x00"})
	if got := (&Reader{root: pi}).model(); got != "Raspberry Pi 5 Model B Rev 1.0" {
		t.Fatalf("model = %q", got)
	}

	pc := machine(t, map[string]string{"sys/devices/virtual/dmi/id/product_name": "VMware Virtual Platform\n"})
	if got := (&Reader{root: pc}).model(); got != "VMware Virtual Platform" {
		t.Fatalf("model = %q", got)
	}

	if got := (&Reader{root: machine(t, nil)}).model(); got != "" {
		t.Fatalf("model = %q, want empty", got)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}

	return false
}
