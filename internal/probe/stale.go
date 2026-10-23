package probe

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// StaleProcess is a running process still executing a PHP binary or libphp
// that has been replaced on disk, i.e. patched but not restarted.
type StaleProcess struct {
	PID    int    `json:"pid"`
	Comm   string `json:"comm"`
	Image  string `json:"image"`
	Reason string `json:"reason"`
}

// StaleScan summarises a process scan.
type StaleScan struct {
	Supported bool           `json:"supported"`
	Scanned   int            `json:"scanned"`
	Denied    int            `json:"denied"` // processes we lacked permission to inspect
	Stale     []StaleProcess `json:"stale"`
}

const deletedSuffix = " (deleted)"

var (
	// Processes that may embed PHP via a shared library (mod_php, LSAPI, ...).
	hostProcRe = regexp.MustCompile(`^(apache2|httpd|httpd-prefork|litespeed|lshttpd|openlitespeed|nginx-unit|unitd)$`)
	libphpRe   = regexp.MustCompile(`/libphp[\d.]*\.so`)
)

// ScanStaleProcesses inspects a Linux /proc tree rooted at procRoot.
// procRoot is a parameter so the logic can be tested with a fake tree.
func ScanStaleProcesses(procRoot string) StaleScan {
	res := StaleScan{Supported: true}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		res.Supported = false
		return res
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		exe, err := os.Readlink(filepath.Join(dir, "exe"))
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				res.Denied++
			}
			continue // kernel threads have no exe; races with exiting processes
		}
		res.Scanned++
		comm := readTrim(filepath.Join(dir, "comm"))

		image := strings.TrimSuffix(exe, deletedSuffix)
		if _, ok := ClassifyName(filepath.Base(image)); ok && strings.HasSuffix(exe, deletedSuffix) {
			res.Stale = append(res.Stale, StaleProcess{PID: pid, Comm: comm, Image: image,
				Reason: "PHP binary was replaced on disk after this process started"})
			continue
		}
		if hostProcRe.MatchString(filepath.Base(image)) || hostProcRe.MatchString(comm) {
			if lib, ok := deletedLibPHP(filepath.Join(dir, "maps")); ok {
				res.Stale = append(res.Stale, StaleProcess{PID: pid, Comm: comm, Image: lib,
					Reason: "libphp was replaced on disk after this process loaded it"})
			} else if lib == "denied" {
				res.Denied++
			}
		}
	}
	sort.Slice(res.Stale, func(i, j int) bool { return res.Stale[i].PID < res.Stale[j].PID })
	return res
}

func deletedLibPHP(mapsPath string) (string, bool) {
	f, err := os.Open(mapsPath)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return "denied", false
		}
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasSuffix(line, deletedSuffix) && libphpRe.MatchString(line) {
			fields := strings.Fields(strings.TrimSuffix(line, deletedSuffix))
			return fields[len(fields)-1], true
		}
	}
	return "", false
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
