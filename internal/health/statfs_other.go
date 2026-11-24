//go:build !linux

package health

func diskUsage(path string) (total, free uint64) { return 0, 0 }
