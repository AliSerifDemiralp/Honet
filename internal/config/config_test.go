package config

import "testing"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	c, err := Parse(nil, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/var/lib/honet" || c.DBPath != "/var/lib/honet/honet.db" || c.Listen != ":8443" || c.PlainHTTP {
		t.Fatalf("bad defaults: %+v", c)
	}
}

func TestEnvDataDir(t *testing.T) {
	c, err := Parse(nil, env(map[string]string{"HONET_DATA_DIR": "/x", "HONET_LISTEN": ":9000"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.DBPath != "/x/honet.db" || c.Listen != ":9000" {
		t.Fatalf("got %+v", c)
	}
}

func TestFlagOverridesEnv(t *testing.T) {
	c, err := Parse([]string{"--db", "/y.db", "--http", "--listen", "127.0.0.1:1"}, env(map[string]string{"HONET_DATA_DIR": "/x"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.DBPath != "/y.db" || !c.PlainHTTP || c.Listen != "127.0.0.1:1" || c.DataDir != "/x" {
		t.Fatalf("got %+v", c)
	}
}

func TestCertNeedsKey(t *testing.T) {
	if _, err := Parse([]string{"--cert", "a"}, env(nil)); err == nil {
		t.Fatal("expected error")
	}
	if _, err := Parse([]string{"--cert", "a", "--key", "b"}, env(nil)); err != nil {
		t.Fatal(err)
	}
}
