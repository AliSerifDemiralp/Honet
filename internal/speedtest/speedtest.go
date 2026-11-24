// Package speedtest measures internet throughput against Cloudflare's speed
// test endpoints (the same ones speed.cloudflare.com uses).
package speedtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultBase is the speed test server.
const DefaultBase = "https://speed.cloudflare.com"

// sizes are the request sizes in bytes; the last one repeats until the
// time limit of the direction is reached.
var sizes = []int64{100_000, 1_000_000, 10_000_000, 25_000_000, 50_000_000}

// Result is one finished test.
type Result struct {
	DownMbps float64
	UpMbps   float64
	LoadedMs float64 // median latency measured while downloading
	Bytes    int64   // data used, both directions
}

// DefaultMaxBytes bounds the data one direction may use. On a fast line
// the 10 second limit alone could use more than a gigabyte.
const DefaultMaxBytes = 100_000_000

// Tester runs speed tests. The zero value uses DefaultBase, 10 seconds and
// DefaultMaxBytes per direction, and http.DefaultClient.
type Tester struct {
	Client   *http.Client
	Base     string
	PerDir   time.Duration
	MaxBytes int64 // per direction; no new request starts past this
}

func (t Tester) defaults() Tester {
	if t.Client == nil {
		t.Client = http.DefaultClient
	}
	if t.Base == "" {
		t.Base = DefaultBase
	}
	if t.PerDir <= 0 {
		t.PerDir = 10 * time.Second
	}
	if t.MaxBytes <= 0 {
		t.MaxBytes = DefaultMaxBytes
	}
	return t
}

// Run measures download, then upload. Each direction stops after PerDir;
// data received up to then counts.
func (t Tester) Run(ctx context.Context) (Result, error) {
	t = t.defaults()
	var r Result

	dctx, cancel := context.WithTimeout(ctx, t.PerDir)
	var wg sync.WaitGroup
	var lat []float64
	wg.Add(1)
	go func() { defer wg.Done(); lat = t.probe(dctx) }()
	n, el, err := t.direction(dctx, t.download)
	cancel()
	wg.Wait()
	r.Bytes += n
	if err != nil {
		return r, fmt.Errorf("download: %w", err)
	}
	r.DownMbps = mbps(n, el)
	r.LoadedMs = median(lat)

	uctx, cancel := context.WithTimeout(ctx, t.PerDir)
	n, el, err = t.direction(uctx, t.upload)
	cancel()
	r.Bytes += n
	if err != nil {
		return r, fmt.Errorf("upload: %w", err)
	}
	r.UpMbps = mbps(n, el)
	return r, ctx.Err()
}

// direction repeats step with growing sizes until ctx ends or the next
// request would exceed MaxBytes. It returns the bytes moved and the time.
func (t Tester) direction(ctx context.Context, step func(context.Context, int64) (int64, error)) (int64, time.Duration, error) {
	start := time.Now()
	var total int64
	for i := 0; ctx.Err() == nil; i++ {
		size := sizes[min(i, len(sizes)-1)]
		if total > 0 && total+size > t.MaxBytes {
			break
		}
		n, err := step(ctx, size)
		total += n
		if err != nil {
			if ctx.Err() != nil {
				break // time limit reached mid-request; partial data counts
			}
			return total, 0, err
		}
	}
	el := time.Since(start)
	if total == 0 {
		return 0, el, errors.New("no data transferred")
	}
	return total, el, nil
}

func (t Tester) download(ctx context.Context, size int64) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.Base+"/__down?bytes="+strconv.FormatInt(size, 10), nil)
	if err != nil {
		return 0, err
	}
	resp, err := t.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.Copy(io.Discard, resp.Body)
}

func (t Tester) upload(ctx context.Context, size int64) (int64, error) {
	body := &zeros{left: size}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Base+"/__up", body)
	if err != nil {
		return 0, err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := t.Client.Do(req)
	if err != nil {
		return body.sent.Load(), err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body.sent.Load(), nil
}

// probe measures round trips of empty requests every 500 ms until ctx ends.
func (t Tester) probe(ctx context.Context) []float64 {
	var out []float64
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		start := time.Now()
		if _, err := t.download(ctx, 0); err == nil {
			out = append(out, float64(time.Since(start).Microseconds())/1000)
		}
		select {
		case <-ctx.Done():
			return out
		case <-tick.C:
		}
	}
}

// zeros is a request body of `left` zero bytes that counts what was read.
type zeros struct {
	left int64
	sent atomic.Int64
}

func (z *zeros) Read(p []byte) (int, error) {
	if z.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > z.left {
		p = p[:z.left]
	}
	clear(p)
	z.left -= int64(len(p))
	z.sent.Add(int64(len(p)))
	return len(p), nil
}

func mbps(n int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) * 8 / d.Seconds() / 1e6
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}
