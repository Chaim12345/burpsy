package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

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
		if _, err := fmt.Sscanf(name, "segment_%d.dat", &segNum); err == nil {
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
		sl.currentName = filepath.Join(dir, fmt.Sprintf("segment_%d.dat", maxSeg))
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

// rotate creates a new segment file.
func (sl *SegmentLog) rotate() error {
	if sl.currentFile != nil {
		sl.currentFile.Close()
	}

	// Find next segment number
	segNum := 0
	if sl.currentName != "" {
		var oldNum int
		if _, err := fmt.Sscanf(filepath.Base(sl.currentName), "segment_%d.dat", &oldNum); err == nil {
			segNum = oldNum + 1
		}
	}

	sl.currentName = filepath.Join(sl.dir, fmt.Sprintf("segment_%d.dat", segNum))
	file, err := os.Create(sl.currentName)
	if err != nil {
		return fmt.Errorf("failed to create new segment: %w", err)
	}

	sl.currentFile = file
	sl.currentOffset = 0
	return nil
}

// Read reads data from a location.
func (sl *SegmentLog) Read(loc Location) ([]byte, error) {
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

// TotalWritten returns the total bytes written across all segments.
func (sl *SegmentLog) TotalWritten() int64 {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	return sl.totalWritten
}

// Close closes the current segment file.
func (sl *SegmentLog) Close() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if sl.currentFile != nil {
		return sl.currentFile.Close()
	}
	return nil
}
