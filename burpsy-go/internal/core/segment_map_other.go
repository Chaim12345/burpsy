//go:build !unix

package core

import "errors"

// segmentMappingSupported is false here, which makes the store keep payload
// bytes resident even when a capture directory is configured. That is the old,
// memory-hungry behaviour, and it is deliberate: span slicing has to be free
// (Header slices once per header), and without a mapping the only way to make
// it free is to hold the bytes.
const segmentMappingSupported = false

var errNoSegmentMapping = errors.New("segment mapping is not supported on this platform")

func mapSegment(int, int64) ([]byte, error) { return nil, errNoSegmentMapping }

func unmapSegment([]byte) error { return nil }
