package target

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Host scans the machine the tool is running on.
type Host struct{}

// NewHost returns a Target for the local machine.
func NewHost() *Host { return &Host{} }

func (*Host) Name() string { return fmt.Sprintf("host (%s/%s)", runtime.GOOS, runtime.GOARCH) }
func (*Host) OS() string   { return runtime.GOOS }

func (*Host) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	// Keep PHP from loading a project-local php.ini from the current directory.
	cmd.Dir = os.TempDir()
	err := cmd.Run()
	return buf.Bytes(), err
}

func (*Host) PathDirs(context.Context) ([]string, error) {
	return dedupe(filepath.SplitList(os.Getenv("PATH"))), nil
}

func (*Host) Glob(_ context.Context, patterns ...string) ([]string, error) {
	var out []string
	for _, p := range patterns {
		m, err := filepath.Glob(expandHome(p))
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", p, err)
		}
		out = append(out, m...)
	}
	return dedupe(out), nil
}

func (*Host) ReadFile(_ context.Context, path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if limit > 0 {
		r = io.LimitReader(f, limit)
	}
	return io.ReadAll(r)
}

func (*Host) RealPath(_ context.Context, path string) (string, error) {
	p, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return filepath.Abs(p)
}

func (*Host) IsExecutable(_ context.Context, path string) bool {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Ext(path), ".exe")
	}
	return fi.Mode().Perm()&0o111 != 0
}

func (*Host) Close(context.Context) error { return nil }

// expandHome expands a leading "~" and %VAR% / $VAR environment references.
func expandHome(p string) string {
	if strings.HasPrefix(p, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[1:])
		}
	}
	if runtime.GOOS == "windows" {
		for _, v := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", "USERPROFILE", "SystemDrive"} {
			if val := os.Getenv(v); val != "" {
				p = strings.ReplaceAll(p, "%"+v+"%", val)
			}
		}
	}
	return p
}
