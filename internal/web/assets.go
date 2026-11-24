package web

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

var (
	assetMu   sync.Mutex
	assetHash = map[string]string{}
)

// asset returns the URL of a static file with a content hash, so browsers
// that cache static files for a day still load new versions at once.
func asset(name string) string {
	assetMu.Lock()
	defer assetMu.Unlock()
	h, ok := assetHash[name]
	if !ok {
		b, err := assets.ReadFile("static/" + name)
		if err == nil {
			sum := sha256.Sum256(b)
			h = hex.EncodeToString(sum[:6])
		}
		assetHash[name] = h
	}
	if h == "" {
		return "/static/" + name
	}
	return "/static/" + name + "?v=" + h
}
