package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/app"
	"github.com/AliSerifDemiralp/honet/internal/auth"
	"github.com/AliSerifDemiralp/honet/internal/config"
	"github.com/AliSerifDemiralp/honet/internal/health"
	"github.com/AliSerifDemiralp/honet/internal/inventory"
	"github.com/AliSerifDemiralp/honet/internal/netmon"
	"github.com/AliSerifDemiralp/honet/internal/oui"
	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
	"github.com/AliSerifDemiralp/honet/internal/scheduler"
	"github.com/AliSerifDemiralp/honet/internal/session"
	"github.com/AliSerifDemiralp/honet/internal/speedtest"
	"github.com/AliSerifDemiralp/honet/internal/store"
	"github.com/AliSerifDemiralp/honet/internal/tlsutil"
	"github.com/AliSerifDemiralp/honet/internal/web"
)

// serveDeps are the parts of serve that touch the real network, so tests
// can replace them.
type serveDeps struct {
	Disc     lan.Discoverer
	Route    func() (string, netip.Addr, error)
	IfaceNet func(string) (netip.Prefix, error)
	Ready    func(net.Addr) // called once the listener is open

	Pinger    netmon.Pinger
	SpeedBase string // speed test server; "" = Cloudflare
}

func serve(ctx context.Context, cfg config.Config, stdout io.Writer) error {
	return serveWith(ctx, cfg, stdout, serveDeps{
		Disc:     lan.NewARPDiscoverer(50, 2*time.Second),
		Route:    app.DefaultRoute,
		IfaceNet: app.InterfacePrefix,
		Pinger:   netmon.NewICMP(),
	})
}

// clockSane reports whether the wall clock looks set (a Pi without an RTC
// boots in 1970 until NTP syncs).
func clockSane(t time.Time) bool { return t.Year() >= 2025 }

func serveWith(ctx context.Context, cfg config.Config, stdout io.Writer, d serveDeps) error {
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	a := auth.New(st, time.Now)
	code, err := a.EnsureSetupCode(ctx)
	if err != nil {
		return err
	}
	if code != "" {
		fmt.Fprintf(stdout, "\n=========================================\n HONET SETUP CODE: %s\n Open the web UI and enter this code to\n create the admin account.\n=========================================\n\n", code)
	}

	settings := func() store.Settings {
		v, err := st.LoadSettings(context.Background())
		if err != nil {
			return store.DefaultSettings()
		}
		return v
	}

	inv := inventory.New(st, time.Now)
	runner := &app.Runner{Inv: inv, Store: st, Disc: d.Disc, Sweep: lan.NewSweepDiscoverer(d.Pinger),
		Prober:   lan.TCPProber{Concurrency: 32, Timeout: 800 * time.Millisecond},
		Resolver: net.DefaultResolver, OUI: oui.Lookup, Route: d.Route, IfaceNet: d.IfaceNet, Now: time.Now,
		Speed:   speedtest.Tester{Client: &http.Client{}, Base: d.SpeedBase},
		NetBIOS: func(ctx context.Context, ip netip.Addr) string { return lan.NetBIOSName(ctx, ip, 700*time.Millisecond) },
		HTTPInfo: func(ctx context.Context, ip netip.Addr, port int) string {
			return lan.HTTPInfo(ctx, ip, port, 2*time.Second)
		}}
	sched := scheduler.New(runner.Run, func() scheduler.Intervals {
		v := settings()
		return scheduler.Intervals{scheduler.KindDiscovery: v.DiscoveryInterval, scheduler.KindPorts: v.PortInterval,
			scheduler.KindSpeed: v.SpeedInterval}
	}, time.Now)
	runner.Enqueue = sched.Enqueue
	seedScheduler(ctx, sched, inv)

	mon := &netmon.Monitor{
		Pinger:   d.Pinger,
		Resolver: net.DefaultResolver,
		Gateway: func() (netip.Addr, error) {
			_, gw, err := d.Route()
			return gw, err
		},
		Targets: func() []string { return settings().LatencyTargets },
		Busy: func() bool {
			r := sched.Status().Running
			return r != nil && r.Kind == scheduler.KindSpeed
		},
		Save: inv.SaveLatency,
		Now:  time.Now,
		Log:  func(s string) { log.Print("honet: " + s) },
	}

	sess := session.NewManager(func() time.Duration { return settings().SessionIdle }, time.Now)
	handler, err := web.New(web.Deps{Store: st, Auth: a, Sess: sess, Inv: inv, Sched: sched,
		Health:  func() health.Health { return health.Read(os.DirFS("/"), cfg.DataDir) },
		Latency: mon.Err,
		HostNet: func() string {
			iface, _, err := d.Route()
			if err != nil {
				return ""
			}
			n, err := d.IfaceNet(iface)
			if err != nil {
				return ""
			}
			return n.String() + " on " + iface
		},
		Secure: !cfg.PlainHTTP, Version: version, DevAssets: cfg.DevAssets, Now: time.Now})
	if err != nil {
		return err
	}

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: log.New(&rateLimitedWriter{out: os.Stderr, every: time.Minute, now: time.Now}, "honet: http: ", 0)}
	scheme := "http"
	if !cfg.PlainHTTP {
		var cert tls.Certificate
		if cfg.CertFile != "" {
			cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		} else {
			cert, err = tlsutil.LoadOrCreate(cfg.DataDir, time.Now)
		}
		if err != nil {
			return fmt.Errorf("TLS certificate: %w", err)
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
		scheme = "https"
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "honet %s listening on %s://%s\n", version, scheme, ln.Addr())

	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); sched.Run(runCtx) }()
	go func() { defer wg.Done(); mon.Run(runCtx, func() time.Duration { return settings().LatencyInterval }) }()
	go func() { defer wg.Done(); maintain(runCtx, st, inv, a) }()

	errc := make(chan error, 1)
	go func() {
		if scheme == "https" {
			errc <- srv.ServeTLS(ln, "", "")
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	if d.Ready != nil {
		d.Ready(ln.Addr())
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	stop()
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutCtx)
	waited := make(chan struct{})
	go func() { wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-shutCtx.Done():
		log.Print("honet: background jobs did not stop in time")
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	return serveErr
}

// maintain prunes old data and checkpoints the WAL once a day.
func maintain(ctx context.Context, st *store.Store, inv *inventory.Inventory, a *auth.Auth) {
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if clockSane(time.Now()) {
			if err := inv.Prune(ctx); err != nil {
				log.Printf("honet: prune: %v", err)
			}
			if err := a.PruneAttempts(ctx); err != nil {
				log.Printf("honet: prune login attempts: %v", err)
			}
			if _, err := st.DB.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
				log.Printf("honet: wal checkpoint: %v", err)
			}
		}
		t.Reset(24 * time.Hour)
	}
}

// seedScheduler tells the scheduler about the last speed test before this
// start, so restarting honet does not trigger a new test every time.
func seedScheduler(ctx context.Context, sched *scheduler.Scheduler, inv *inventory.Inventory) {
	if last, err := inv.LastSpeedTest(ctx); err == nil && last != nil {
		sched.MarkRun(scheduler.KindSpeed, last.At)
	}
}
