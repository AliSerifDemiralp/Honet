package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sub", "honet.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}

func TestOpenCreatesSchema(t *testing.T) {
	s, p := openTemp(t)
	var v int
	if err := s.DB.QueryRow(`SELECT version FROM schema_version`).Scan(&v); err != nil || v != len(migrations) {
		t.Fatalf("version %d err %v", v, err)
	}
	if _, err := s.DB.Exec(`SELECT id FROM devices LIMIT 1`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var n int
	s2.DB.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&n)
	if n != 1 {
		t.Fatalf("schema_version rows %d", n)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	got, err := s.LoadSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, DefaultSettings()) {
		t.Fatalf("defaults %+v", got)
	}
	want := DefaultSettings()
	want.DiscoveryInterval = 2 * time.Minute
	want.CIDR = "192.168.1.0/24"
	want.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.168.1.2/32")}
	if err := s.SaveSettings(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, _ = s.LoadSettings(ctx)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestDefaults(t *testing.T) {
	d := DefaultSettings()
	if d.DiscoveryInterval != 5*time.Minute || d.PortInterval != time.Hour || d.SessionIdle != 15*time.Minute || d.WatchAfter != 15*time.Minute {
		t.Fatalf("%+v", d)
	}
}

func TestTimeRoundTrip(t *testing.T) {
	now := time.Date(2026, 11, 23, 10, 0, 0, 123, time.FixedZone("x", 3*3600))
	got, err := ParseTime(FormatTime(now))
	if err != nil || !got.Equal(now) || got.Location() != time.UTC {
		t.Fatalf("%v %v", got, err)
	}
}

func TestMigrationV3DeviceColumns(t *testing.T) {
	s, _ := openTemp(t)
	for _, col := range []string{"http_info", "is_gateway"} {
		var n int
		s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name = ?`, col).Scan(&n)
		if n != 1 {
			t.Errorf("devices.%s missing", col)
		}
	}
}
