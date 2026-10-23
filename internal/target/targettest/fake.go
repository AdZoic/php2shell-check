// Package targettest provides an in-memory target.Target for tests.
package targettest

import (
	"context"
	"errors"
	"path"
	"sort"

	"github.com/AdZoic/php2shell-check/internal/target"
)

// Fake is an in-memory, Linux-like target.
type Fake struct {
	Goos    string
	PathEnv []string
	Files   map[string][]byte // regular files
	Execs   map[string]bool   // executable files (by real path)
	Links   map[string]string // symlink -> target
	RunFunc func(name string, args []string) ([]byte, error)
}

var _ target.Target = (*Fake)(nil)

func (f *Fake) Name() string { return "fake" }

func (f *Fake) OS() string {
	if f.Goos == "" {
		return "linux"
	}
	return f.Goos
}

func (f *Fake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if f.RunFunc == nil {
		return nil, errors.New("targettest: no RunFunc")
	}
	return f.RunFunc(name, args)
}

func (f *Fake) PathDirs(context.Context) ([]string, error) { return f.PathEnv, nil }

// Glob matches patterns against every known path, in sorted order per pattern.
func (f *Fake) Glob(_ context.Context, patterns ...string) ([]string, error) {
	all := map[string]bool{}
	for p := range f.Files {
		all[p] = true
	}
	for p := range f.Execs {
		all[p] = true
	}
	for p := range f.Links {
		all[p] = true
	}
	keys := make([]string, 0, len(all))
	for p := range all {
		keys = append(keys, p)
	}
	sort.Strings(keys)

	var out []string
	seen := map[string]bool{}
	for _, pat := range patterns {
		for _, p := range keys {
			if ok, _ := path.Match(pat, p); ok && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func (f *Fake) ReadFile(_ context.Context, p string, limit int64) ([]byte, error) {
	b, ok := f.Files[p]
	if !ok {
		return nil, target.ErrNotFound
	}
	if limit > 0 && int64(len(b)) > limit {
		b = b[:limit]
	}
	return b, nil
}

func (f *Fake) RealPath(_ context.Context, p string) (string, error) {
	for i := 0; i < 16; i++ {
		t, ok := f.Links[p]
		if !ok {
			return p, nil
		}
		p = t
	}
	return "", errors.New("targettest: symlink loop")
}

func (f *Fake) IsExecutable(ctx context.Context, p string) bool {
	r, err := f.RealPath(ctx, p)
	return err == nil && f.Execs[r]
}

func (f *Fake) Close(context.Context) error { return nil }
