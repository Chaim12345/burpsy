//go:build unix

package core

import "syscall"

// segmentMappingSupported gates the store's decision to stop retaining payload
// bytes: without a mapping, slicing a span would mean re-reading the whole
// message, so on a platform that cannot map we keep the bytes resident instead.
const segmentMappingSupported = true

// mapSegment maps a whole sealed segment read-only. The fd may be closed as
// soon as this returns — the mapping keeps its own reference to the file.
func mapSegment(fd int, size int64) ([]byte, error) {
	return syscall.Mmap(fd, 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
}

func unmapSegment(b []byte) error { return syscall.Munmap(b) }
