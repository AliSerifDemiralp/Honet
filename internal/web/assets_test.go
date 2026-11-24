package web

import (
	"regexp"
	"strings"
	"testing"
)

func TestStaticAssetsVersioned(t *testing.T) {
	e := newEnv(t)
	s := body(e.loggedIn().get("/"))
	re := regexp.MustCompile(`/static/(honet\.js|honet\.css|vendor/bootstrap\.min\.css|vendor/bootstrap\.bundle\.min\.js)\?v=[0-9a-f]{12}"`)
	if n := len(re.FindAllString(s, -1)); n != 4 {
		t.Fatalf("%d versioned assets in %s", n, s[:strings.Index(s, "</head>")])
	}
	if w := e.browser().get(asset("honet.js")); w.Code != 200 || !strings.Contains(body(w), "Honet UI") {
		t.Fatalf("versioned URL not served: %d", w.Code)
	}
}
