package target

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// CommandRunner runs a local program and returns stdout and stderr separately.
// It exists so the container target can be unit-tested without Docker.
type CommandRunner interface {
	Output(ctx context.Context, name string, args ...string) (stdout []byte, stderr string, err error)
}

// ExecRunner is the real CommandRunner backed by os/exec.
type ExecRunner struct{}

func (ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.Bytes(), errb.String(), err
}

// ExitCode returns the process exit code, or -1 if err is not an exit error.
func ExitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// Container scans a container image by starting a locked-down, network-less
// container from it and running probes with `<engine> exec`. Works with any
// Docker-compatible engine (docker, podman, nerdctl) from any host OS.
type Container struct {
	engine string
	image  string
	id     string
	run    CommandRunner
	path   []string
}

const notFoundExit = 44

// keepAlive keeps the container idle without needing a specific init.
const keepAlive = `command -v sleep >/dev/null 2>&1 && exec sleep 3600; exec tail -f /dev/null`

// StartContainer starts a scan container. The caller must Close it.
func StartContainer(ctx context.Context, run CommandRunner, engine, image string) (*Container, error) {
	if run == nil {
		run = ExecRunner{}
	}
	args := []string{
		"run", "-d", "--rm",
		"--network", "none", // the probe never needs network
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only", "--tmpfs", "/tmp",
		"--pull", "missing",
		"--label", "io.php2shell-check.scan=1",
		"--entrypoint", "sh",
		image, "-c", keepAlive,
	}
	out, stderr, err := run.Output(ctx, engine, args...)
	if err != nil {
		msg := strings.TrimSpace(stderr)
		if strings.Contains(msg, "executable file not found") || strings.Contains(msg, `"sh"`) {
			return nil, fmt.Errorf("image %s has no /bin/sh; shell-less (distroless) images are not supported yet: %s", image, msg)
		}
		return nil, fmt.Errorf("%s run %s: %w: %s", engine, image, err, msg)
	}
	id := strings.TrimSpace(string(out))
	if id == "" {
		return nil, fmt.Errorf("%s run %s: empty container id", engine, image)
	}
	return &Container{engine: engine, image: image, id: id, run: run}, nil
}

func (c *Container) Name() string { return "image " + c.image }
func (c *Container) OS() string   { return "linux" }

func (c *Container) exec(ctx context.Context, args ...string) ([]byte, string, error) {
	full := append([]string{"exec", c.id}, args...)
	return c.run.Output(ctx, c.engine, full...)
}

func (c *Container) sh(ctx context.Context, script string, args ...string) ([]byte, string, error) {
	return c.exec(ctx, append([]string{"sh", "-c", script, "sh"}, args...)...)
}

func (c *Container) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, stderr, err := c.exec(ctx, append([]string{name}, args...)...)
	return append(out, stderr...), err
}

func (c *Container) PathDirs(ctx context.Context) ([]string, error) {
	if c.path != nil {
		return c.path, nil
	}
	out, stderr, err := c.sh(ctx, `printf '%s' "$PATH"`)
	if err != nil {
		return nil, fmt.Errorf("read PATH: %w: %s", err, stderr)
	}
	c.path = dedupe(strings.Split(string(out), ":"))
	return c.path, nil
}

// Glob expands all patterns in a single exec to keep scans fast.
func (c *Container) Glob(ctx context.Context, patterns ...string) ([]string, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	const script = `for p in "$@"; do for f in $p; do [ -e "$f" ] && printf '%s\n' "$f"; done; done; exit 0`
	out, stderr, err := c.sh(ctx, script, patterns...)
	if err != nil {
		return nil, fmt.Errorf("glob in container: %w: %s", err, stderr)
	}
	return dedupe(splitLines(string(out))), nil
}

func (c *Container) ReadFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	script := `[ -e "$1" ] || exit ` + strconv.Itoa(notFoundExit) + `; cat "$1"`
	args := []string{path}
	if limit > 0 {
		script = `[ -e "$1" ] || exit ` + strconv.Itoa(notFoundExit) + `; head -c "$2" "$1"`
		args = append(args, strconv.FormatInt(limit, 10))
	}
	out, stderr, err := c.sh(ctx, script, args...)
	if ExitCode(err) == notFoundExit {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w: %s", path, err, stderr)
	}
	return out, nil
}

func (c *Container) RealPath(ctx context.Context, path string) (string, error) {
	out, _, err := c.sh(ctx, `[ -e "$1" ] || exit `+strconv.Itoa(notFoundExit)+`; readlink -f "$1" 2>/dev/null || printf '%s' "$1"`, path)
	if ExitCode(err) == notFoundExit {
		return "", ErrNotFound
	}
	if err != nil {
		return path, nil // best effort: fall back to the given path
	}
	if p := strings.TrimSpace(string(out)); p != "" {
		return p, nil
	}
	return path, nil
}

func (c *Container) IsExecutable(ctx context.Context, path string) bool {
	_, _, err := c.sh(ctx, `[ -f "$1" ] && [ -x "$1" ]`, path)
	return err == nil
}

func (c *Container) Close(ctx context.Context) error {
	if c.id == "" {
		return nil
	}
	_, stderr, err := c.run.Output(ctx, c.engine, "rm", "-f", c.id)
	if err != nil {
		return fmt.Errorf("%s rm -f %s: %w: %s", c.engine, c.id, err, stderr)
	}
	c.id = ""
	return nil
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimRight(l, "\r"); l != "" {
			out = append(out, l)
		}
	}
	return out
}
