// Package target abstracts "the machine being scanned". The same discovery and
// inspection code runs against the local host (Linux, macOS, Windows) or inside
// a container image, which keeps the scanning logic in one place.
package target

import (
	"context"
	"errors"
)

// ErrNotFound is returned by ReadFile/RealPath when a path does not exist.
var ErrNotFound = errors.New("target: not found")

// Target is the minimal set of operations the scanner needs.
type Target interface {
	// Name is a human label: "host (linux/amd64)", "image php:8.3-fpm".
	Name() string
	// OS is the operating system of the target ("linux", "darwin", "windows").
	OS() string
	// Run executes a program on the target and returns combined output.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// PathDirs returns the directories on the target's $PATH.
	PathDirs(ctx context.Context) ([]string, error)
	// Glob expands shell patterns and returns every match (deduplicated, in order).
	Glob(ctx context.Context, patterns ...string) ([]string, error)
	// ReadFile returns a file's contents, capped at limit bytes (0 = no cap).
	ReadFile(ctx context.Context, path string, limit int64) ([]byte, error)
	// RealPath resolves symlinks to a canonical path.
	RealPath(ctx context.Context, path string) (string, error)
	// IsExecutable reports whether path is a regular, executable file.
	IsExecutable(ctx context.Context, path string) bool
	// Close releases resources (e.g. stops a scan container).
	Close(ctx context.Context) error
}

// dedupe keeps first-seen order.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok || s == "" {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
