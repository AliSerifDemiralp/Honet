// Command honet is a lightweight home network monitor.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/AliSerifDemiralp/honet/internal/config"

	_ "time/tzdata"
)

var version = "dev"

const usage = `usage: honet <command> [flags]

commands:
  serve            run the web UI and scanners
  reset-password   reset the admin password
  version          print the version

flags (serve, reset-password):
  --data-dir DIR   data directory (default /var/lib/honet, env HONET_DATA_DIR)
  --db FILE        database file (default DATA_DIR/honet.db)
  --listen ADDR    listen address (default :8443, env HONET_LISTEN)
  --http           serve plain HTTP instead of HTTPS
  --cert/--key     use this TLS certificate instead of a self-signed one
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "honet %s\n", version)
		return 0
	case "serve", "reset-password":
		cfg, err := config.Parse(args[1:], os.Getenv)
		if err != nil {
			fmt.Fprintf(stderr, "honet: %v\n", err)
			return 2
		}
		if args[0] == "serve" {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			err = serve(ctx, cfg, stdout)
		} else {
			err = resetPassword(cfg, os.Stdin, stdout, func() (string, error) {
				b, err := term.ReadPassword(int(os.Stdin.Fd()))
				return string(b), err
			})
		}
		if err != nil {
			fmt.Fprintf(stderr, "honet: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
