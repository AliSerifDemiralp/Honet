package store

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestMigrationV2Tables(t *testing.T) {
	s, _ := openTemp(t)
	var v int
	s.DB.QueryRow(`SELECT version FROM schema_version`).Scan(&v)
	if v < 2 {
		t.Fatalf("version %d", v)
	}
	for _, tbl := range []string{"people", "person_devices", "presence", "latency_5m", "speedtests"} {
		var n int
		s.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n)
		if n != 1 {
			t.Errorf("table %s missing", tbl)
		}
	}
}

func TestSettingsPhase2Defaults(t *testing.T) {
	d := DefaultSettings()
	if d.SpeedInterval != 3*time.Hour || d.LatencyInterval != time.Minute || d.PiLimitMbps != 25 ||
		!reflect.DeepEqual(d.LatencyTargets, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Fatalf("%+v", d)
	}
}

func TestSettingsPhase2RoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	want := DefaultSettings()
	want.SpeedInterval = 6 * time.Hour
	want.LatencyInterval = 0
	want.LatencyTargets = []string{"9.9.9.9"}
	want.PiLimitMbps = 40.5
	if err := s.SaveSettings(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, _ := s.LoadSettings(ctx)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	want.LatencyTargets = nil
	s.SaveSettings(ctx, want)
	got, _ = s.LoadSettings(ctx)
	if len(got.LatencyTargets) != 0 {
		t.Fatalf("empty targets came back as %v", got.LatencyTargets)
	}
}
