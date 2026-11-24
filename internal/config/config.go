// Package config parses honet's command-line flags and environment.
package config

import (
	"errors"
	"flag"
	"io"
	"path"
)

// Config holds runtime settings that are fixed for the life of the process.
type Config struct {
	DataDir   string // HONET_DATA_DIR, --data-dir
	DBPath    string // --db; defaults to <DataDir>/honet.db
	Listen    string // HONET_LISTEN, --listen
	PlainHTTP bool   // --http
	CertFile  string // --cert
	KeyFile   string // --key
	DevAssets string // --dev-assets: read templates/static from disk
}

// Parse reads flags from args, falling back to environment, then defaults.
func Parse(args []string, getenv func(string) string) (Config, error) {
	c := Config{DataDir: "/var/lib/honet", Listen: ":8443"}
	if v := getenv("HONET_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := getenv("HONET_LISTEN"); v != "" {
		c.Listen = v
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.DataDir, "data-dir", c.DataDir, "data directory")
	fs.StringVar(&c.DBPath, "db", "", "database path")
	fs.StringVar(&c.Listen, "listen", c.Listen, "listen address")
	fs.BoolVar(&c.PlainHTTP, "http", false, "serve plain HTTP instead of HTTPS")
	fs.StringVar(&c.CertFile, "cert", "", "TLS certificate file")
	fs.StringVar(&c.KeyFile, "key", "", "TLS key file")
	fs.StringVar(&c.DevAssets, "dev-assets", "", "read web assets from this directory")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if c.DBPath == "" {
		c.DBPath = path.Join(c.DataDir, "honet.db")
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return Config{}, errors.New("--cert and --key must be given together")
	}
	return c, nil
}
