package target

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestHostFileOps(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	exe := filepath.Join(dir, "php8.3")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	if err := os.WriteFile(exe, []byte("hello world"), 0o755); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := NewHost()

	got, err := h.Glob(ctx, filepath.Join(dir, "php*"), filepath.Join(dir, "php*"))
	if err != nil || len(got) != 1 {
		t.Fatalf("Glob=%v err=%v (expected one deduplicated match)", got, err)
	}
	if !h.IsExecutable(ctx, exe) {
		t.Error("expected executable")
	}
	if h.IsExecutable(ctx, plain) || h.IsExecutable(ctx, dir) {
		t.Error("plain file / dir must not be executable")
	}
	b, err := h.ReadFile(ctx, exe, 5)
	if err != nil || string(b) != "hello" {
		t.Fatalf("ReadFile limit: %q %v", b, err)
	}
	if _, err := h.ReadFile(ctx, filepath.Join(dir, "missing"), 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := h.RealPath(ctx, filepath.Join(dir, "missing")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := h.Glob(ctx, "[bad"); err == nil {
		t.Error("expected bad pattern error")
	}
	if !strings.Contains(h.Name(), runtime.GOOS) || h.OS() != runtime.GOOS {
		t.Error("host name/os mismatch")
	}
}

// fakeRunner records calls and replays scripted responses.
type fakeRunner struct {
	calls   [][]string
	respond func(args []string) ([]byte, string, error)
}

func (f *fakeRunner) Output(_ context.Context, name string, args ...string) ([]byte, string, error) {
	full := append([]string{name}, args...)
	f.calls = append(f.calls, full)
	return f.respond(full)
}

// exitErr produces a real *exec.ExitError with the given code.
func exitErr(t *testing.T, code int) error {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	err := exec.Command("sh", "-c", "exit "+strconv.Itoa(code)).Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	return err
}

func TestContainerLifecycle(t *testing.T) {
	ctx := context.Background()
	notFound := exitErr(t, notFoundExit)
	f := &fakeRunner{respond: func(a []string) ([]byte, string, error) {
		switch {
		case a[1] == "run":
			return []byte("abc123\n"), "", nil
		case a[1] == "rm":
			return nil, "", nil
		case strings.Contains(strings.Join(a, " "), `printf '%s' "$PATH"`):
			return []byte("/usr/local/bin:/usr/bin:/usr/bin"), "", nil
		case strings.Contains(a[5], "for p in"):
			return []byte("/usr/local/bin/php\n/usr/local/sbin/php-fpm\n/usr/local/bin/php\n"), "", nil
		case strings.Contains(a[5], "cat \"$1\"") && a[len(a)-1] == "/missing":
			return nil, "", notFound
		case strings.Contains(a[5], "head -c"):
			return []byte("12345"), "", nil
		}
		return nil, "unexpected", errors.New("unexpected call")
	}}
	c, err := StartContainer(ctx, f, "docker", "php:8.3-fpm")
	if err != nil {
		t.Fatal(err)
	}
	run := strings.Join(f.calls[0], " ")
	for _, want := range []string{"--network none", "--cap-drop ALL", "--read-only", "--rm", "php:8.3-fpm"} {
		if !strings.Contains(run, want) {
			t.Errorf("run args missing %q: %s", want, run)
		}
	}
	if c.Name() != "image php:8.3-fpm" || c.OS() != "linux" {
		t.Error("bad name/os")
	}

	dirs, err := c.PathDirs(ctx)
	if err != nil || len(dirs) != 2 {
		t.Fatalf("PathDirs=%v %v", dirs, err)
	}
	n := len(f.calls)
	if _, _ = c.PathDirs(ctx); len(f.calls) != n {
		t.Error("PathDirs should be cached")
	}

	g, err := c.Glob(ctx, "/usr/local/bin/php*", "/usr/local/sbin/php-fpm*")
	if err != nil || len(g) != 2 {
		t.Fatalf("Glob=%v %v", g, err)
	}
	if _, err := c.ReadFile(ctx, "/missing", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if b, err := c.ReadFile(ctx, "/x", 5); err != nil || string(b) != "12345" {
		t.Fatalf("limited read %q %v", b, err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal("Close must be idempotent")
	}
}

func TestStartContainerErrors(t *testing.T) {
	ctx := context.Background()
	f := &fakeRunner{respond: func([]string) ([]byte, string, error) {
		return nil, `exec: "sh": executable file not found in $PATH`, errors.New("exit 127")
	}}
	if _, err := StartContainer(ctx, f, "docker", "gcr.io/distroless/static"); err == nil ||
		!strings.Contains(err.Error(), "distroless") {
		t.Fatalf("want distroless hint, got %v", err)
	}
	f.respond = func([]string) ([]byte, string, error) { return []byte("  \n"), "", nil }
	if _, err := StartContainer(ctx, f, "docker", "x"); err == nil {
		t.Fatal("want error on empty container id")
	}
}

func TestExitCode(t *testing.T) {
	if ExitCode(errors.New("x")) != -1 {
		t.Fatal("non exit error should be -1")
	}
	if ExitCode(exitErr(t, 3)) != 3 {
		t.Fatal("want 3")
	}
}
