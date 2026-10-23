// Command php2shell-check finds PHP installations affected by PHP2Shell
// (CVE-2026-109618, CVE-2026-109619) on hosts and container images.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/AdZoic/php2shell-check/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], cli.DefaultDeps())
	stop()
	os.Exit(code)
}
