package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(out.String(), "honet dev") {
		t.Fatalf("got %q", out.String())
	}
}

func TestRunUnknown(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"nope"}, &out, &errb); code != 2 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(errb.String(), "usage") {
		t.Fatal("no usage")
	}
}
