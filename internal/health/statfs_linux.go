//go:build linux

package health

import "syscall"

func diskUsage(path string) (total, free uint64) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, 0
	}
	return uint64(s.Blocks) * uint64(s.Bsize), uint64(s.Bavail) * uint64(s.Bsize)
}
