package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// segmentNameFormat is the one place the on-disk segment filename is spelled.
// It is shared with VerifyCaptureDir, which used to carry its own, different
// spelling and so matched no files at all.
const segmentNameFormat = "segment_%d.dat"

// Location represents a location in a segment file.
type Location struct {
	Segment string
	Offset  int64
	Length  int64
}

// SegmentLog manages append-only segment files.
type SegmentLog struct {
	mu            sync.Mutex
	dir           string
	targetBytes   uint64
	currentFile   *os.File
	currentName   string
	currentOffset int64
	totalWritten  int64
	// mappings holds one read-only mapping per sealed segment, created on first
	// read and kept until Close. They are never evicted while the log is open,
	// which is what lets ReadAt hand out slices that stay valid after the lock
	// is dropped. The pages are file-backed and clean, so the kernel can
	// reclaim them under pressure without any of them being written to swap —
	// unlike the same bytes held on the Go heap.
	mappings map[string][]byte
}

// NewSegmentLog creates a new segment log in the given directory.
func NewSegmentLog(dir string, targetBytes uint64) (*SegmentLog, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create segment directory: %w", err)
	}

	sl := &SegmentLog{
		dir:         dir,
		targetBytes: targetBytes,
	}

	// Find existing segments and determine current offset
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read segment directory: %w", err)
	}

	maxSeg := -1
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		var segNum int
		if _, err := fmt.Sscanf(name, segmentNameFormat, &segNum); err == nil {
			if segNum > maxSeg {
				maxSeg = segNum
			}
			info, err := entry.Info()
			if err == nil {
				sl.totalWritten += info.Size()
			}
		}
	}

	if maxSeg >= 0 {
		sl.currentName = filepath.Join(dir, fmt.Sprintf(segmentNameFormat, maxSeg))
		file, err := os.OpenFile(sl.currentName, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open current segment: %w", err)
		}
		sl.currentFile = file
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to stat current segment: %w", err)
		}
		sl.currentOffset = info.Size()
	}

	return sl, nil
}

// Append writes data to the current segment, rotating if necessary.
func (sl *SegmentLog) Append(data []byte) (Location, error) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	// Check if we need to rotate
	if sl.currentFile == nil || uint64(sl.currentOffset)+uint64(len(data)) > sl.targetBytes {
		if err := sl.rotate(); err != nil {
			return Location{}, fmt.Errorf("failed to rotate segment: %w", err)
		}
	}

	offset := sl.currentOffset
	n, err := sl.currentFile.Write(data)
	if err != nil {
		return Location{}, fmt.Errorf("failed to write to segment: %w", err)
	}

	sl.currentOffset += int64(n)
	sl.totalWritten += int64(n)

	return Location{
		Segment: sl.currentName,
		Offset:  offset,
		Length:  int64(n),
	}, nil
}

// rotate seals the current segment and creates a new one. Sealing means the
// bytes are on the platter and the file will never be appended to again, which
// is precisely the precondition ReadAt needs before it will map a segment.
func (sl *SegmentLog) rotate() error {
	if sl.currentFile != nil {
		if err := sl.currentFile.Sync(); err != nil {
			return fmt.Errorf("failed to seal segment %s: %w", sl.currentName, err)
		}
		sl.currentFile.Close()
	}

	// Find next segment number
	segNum := 0
	if sl.currentName != "" {
		var oldNum int
		if _, err := fmt.Sscanf(filepath.Base(sl.currentName), segmentNameFormat, &oldNum); err == nil {
			segNum = oldNum + 1
		}
	}

	sl.currentName = filepath.Join(sl.dir, fmt.Sprintf(segmentNameFormat, segNum))
	file, err := os.Create(sl.currentName)
	if err != nil {
		return fmt.Errorf("failed to create new segment: %w", err)
	}

	sl.currentFile = file
	sl.currentOffset = 0
	return nil
}

// Mappable reports whether this log can serve reads out of mappings. The store
// only stops retaining payload bytes when this is true, because a span has to
// be free to slice: Header slices once per header, and a copying read path
// would re-read the entire message for each one.
func (sl *SegmentLog) Mappable() bool { return segmentMappingSupported }

// ReadAt returns the bytes at loc without copying them where it can. For a
// sealed segment the result is a view into a read-only mapping that stays valid
// until Close, and must not be mutated.
//
// The segment currently being appended to is deliberately not mapped. A mapping
// has the length the file had when it was made, and touching a page beyond the
// end of the file raises SIGBUS rather than returning an error — so the active
// segment is read with pread, costing one allocation per read until rotation
// seals it. Sealing before mapping is the whole reason rotation syncs.
func (sl *SegmentLog) ReadAt(loc Location) ([]byte, error) {
	if loc.Segment == "" {
		return nil, fmt.Errorf("location carries no segment: nothing to read")
	}
	if mapped, ok := sl.mapping(loc.Segment); ok {
		end := loc.Offset + loc.Length
		if loc.Offset < 0 || loc.Length < 0 || end > int64(len(mapped)) {
			return nil, fmt.Errorf("location %s offset %d len %d falls outside the %d-byte segment",
				loc.Segment, loc.Offset, loc.Length, len(mapped))
		}
		return mapped[loc.Offset:end], nil
	}
	return sl.pread(loc)
}

// mapping returns a mapping of a sealed segment, creating it on first use. It
// reports false for the active segment, and for any failure to map: every such
// case has a working pread fallback, so a mapping that cannot be made is a
// performance question rather than a correctness one.
func (sl *SegmentLog) mapping(name string) ([]byte, bool) {
	if !segmentMappingSupported {
		return nil, false
	}
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if name == sl.currentName {
		return nil, false
	}
	if m, ok := sl.mappings[name]; ok {
		return m, true
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() == 0 {
		return nil, false
	}
	m, err := mapSegment(int(file.Fd()), info.Size())
	if err != nil {
		return nil, false
	}
	if sl.mappings == nil {
		sl.mappings = make(map[string][]byte)
	}
	sl.mappings[name] = m
	return m, true
}

// pread reads a location into a fresh buffer the caller owns.
func (sl *SegmentLog) pread(loc Location) ([]byte, error) {
	file, err := os.Open(loc.Segment)
	if err != nil {
		return nil, fmt.Errorf("failed to open segment: %w", err)
	}
	defer file.Close()

	data := make([]byte, loc.Length)
	n, err := file.ReadAt(data, loc.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read from segment: %w", err)
	}
	if int64(n) != loc.Length {
		return nil, fmt.Errorf("short read: expected %d, got %d", loc.Length, n)
	}

	return data, nil
}

// Read returns a private copy of the bytes at loc. Prefer ReadAt, which avoids
// the copy for sealed segments; Read is for callers that need to own the buffer
// and outlive the log.
func (sl *SegmentLog) Read(loc Location) ([]byte, error) {
	b, err := sl.ReadAt(loc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

// TotalWritten returns the total bytes written across all segments.
func (sl *SegmentLog) TotalWritten() int64 {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	return sl.totalWritten
}

// Sync seals the active segment without dropping any mapping, so it is safe to
// call while readers are still working. This — not Close — is the shutdown call:
// at exit the kernel releases mappings anyway, so unmapping buys nothing, while
// getting the tail of the capture onto the platter buys everything.
func (sl *SegmentLog) Sync() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if sl.currentFile == nil {
		return nil
	}
	if err := sl.currentFile.Sync(); err != nil {
		return fmt.Errorf("failed to seal segment %s: %w", sl.currentName, err)
	}
	return nil
}

// Close drops every mapping and closes the current segment file. Any slice
// handed out by ReadAt is invalid afterwards — reading one is a segmentation
// fault, not an error return — so Close belongs at process shutdown, once
// nothing can still be holding a message.
func (sl *SegmentLog) Close() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	var firstErr error
	for name, m := range sl.mappings {
		if err := unmapSegment(m); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to unmap segment %s: %w", name, err)
		}
		delete(sl.mappings, name)
	}

	if sl.currentFile != nil {
		// Seal on the way out as well as on rotation: without this the last
		// segment's tail is only in the page cache, so a capture that was never
		// large enough to rotate is the one most at risk of losing its end.
		if err := sl.currentFile.Sync(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to seal segment %s: %w", sl.currentName, err)
		}
		if err := sl.currentFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		sl.currentFile = nil
	}
	return firstErr
}
