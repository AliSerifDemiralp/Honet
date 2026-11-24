package speedtest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// fakeCloudflare serves /__down?bytes=N and /__up like speed.cloudflare.com.
// pause is slept after every 64 KiB chunk written.
func fakeCloudflare(t *testing.T, pause time.Duration) *httptest.Server {
	t.Helper()
	chunk := make([]byte, 64<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__down":
			n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
			w.Header().Set("Content-Length", strconv.Itoa(n))
			for n > 0 {
				c := chunk
				if n < len(c) {
					c = c[:n]
				}
				if _, err := w.Write(c); err != nil {
					return
				}
				n -= len(c)
				if pause > 0 {
					w.(http.Flusher).Flush()
					select {
					case <-time.After(pause):
					case <-r.Context().Done():
						return
					}
				}
			}
		case "/__up":
			io.Copy(io.Discard, r.Body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSpeedMeasures(t *testing.T) {
	srv := fakeCloudflare(t, 0)
	r, err := Tester{Client: srv.Client(), Base: srv.URL, PerDir: 300 * time.Millisecond}.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.DownMbps <= 0 || r.UpMbps <= 0 || r.LoadedMs <= 0 || r.Bytes < 100_000 {
		t.Fatalf("%+v", r)
	}
}

func TestSpeedStopsAtDeadline(t *testing.T) {
	srv := fakeCloudflare(t, 50*time.Millisecond)
	start := time.Now()
	r, err := Tester{Client: srv.Client(), Base: srv.URL, PerDir: 300 * time.Millisecond}.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 1500*time.Millisecond {
		t.Fatalf("took %v", el)
	}
	if r.DownMbps <= 0 {
		t.Fatalf("partial reads must count: %+v", r)
	}
}

func TestSpeedStalledServer(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	start := time.Now()
	_, err := Tester{Client: srv.Client(), Base: srv.URL, PerDir: 200 * time.Millisecond}.Run(context.Background())
	if err == nil {
		t.Fatal("want error from a stalled server")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("took %v", el)
	}
}

func TestSpeedServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 500)
	}))
	defer srv.Close()
	if _, err := (Tester{Client: srv.Client(), Base: srv.URL, PerDir: 200 * time.Millisecond}).Run(context.Background()); err == nil {
		t.Fatal("want error on HTTP 500")
	}
}

func TestSpeedStopsAtByteBudget(t *testing.T) {
	srv := fakeCloudflare(t, 0)
	r, err := Tester{Client: srv.Client(), Base: srv.URL, PerDir: 5 * time.Second, MaxBytes: 1_200_000}.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 100 kB + 1 MB per direction; the next 10 MB request would exceed the budget.
	if r.Bytes != 2_200_000 {
		t.Fatalf("bytes %d", r.Bytes)
	}
}
