package core

import (
	"encoding/binary"
	"fmt"
)

// A MessageShape is nothing but spans, so it can be persisted directly instead
// of being re-derived. That is the difference between a restore that reads the
// index and one that has to touch every captured byte to parse it again: the
// parse is cheap, but faulting in a page per message to feed it is not.
//
// The encoding is a run of unsigned varints, which suits spans: offsets into a
// message are small, so most take one or two bytes. Roughly 50 bytes per
// message in practice, against the ~4.8 KB average message it saves reading.

// EncodeShape serialises a shape for the durable mirror.
func EncodeShape(s MessageShape) []byte {
	out := make([]byte, 0, 32+len(s.Headers)*8)
	out = binary.AppendUvarint(out, uint64(s.Direction))
	for _, span := range []Span{s.FirstToken, s.SecondToken, s.ThirdToken, s.Body} {
		out = binary.AppendUvarint(out, uint64(span.Offset))
		out = binary.AppendUvarint(out, uint64(span.Len))
	}
	out = binary.AppendUvarint(out, uint64(len(s.Headers)))
	for _, h := range s.Headers {
		out = binary.AppendUvarint(out, uint64(h.Name.Offset))
		out = binary.AppendUvarint(out, uint64(h.Name.Len))
		out = binary.AppendUvarint(out, uint64(h.Value.Offset))
		out = binary.AppendUvarint(out, uint64(h.Value.Len))
	}
	return out
}

// DecodeShape reads back a shape written by EncodeShape.
//
// A truncated or over-long buffer is an error, never a partial shape. A shape is
// the map by which every span is resolved, so a half-decoded one would not fail
// loudly — it would quietly resolve headers to the wrong bytes, which is exactly
// the silent mis-resolution the span model exists to rule out.
func DecodeShape(b []byte) (MessageShape, error) {
	d := decoder{buf: b}
	var s MessageShape
	dir, err := d.uvarint("direction")
	if err != nil {
		return MessageShape{}, err
	}
	s.Direction = Direction(dir)

	spans := [...]*Span{&s.FirstToken, &s.SecondToken, &s.ThirdToken, &s.Body}
	names := [...]string{"first token", "second token", "third token", "body"}
	for i, span := range spans {
		if *span, err = d.span(names[i]); err != nil {
			return MessageShape{}, err
		}
	}

	count, err := d.uvarint("header count")
	if err != nil {
		return MessageShape{}, err
	}
	// Each header costs at least four bytes to encode, so a count that could not
	// possibly fit in what is left is a corrupt buffer rather than a large
	// message — refuse it before allocating for it.
	if count > uint64(len(b)) {
		return MessageShape{}, fmt.Errorf("shape claims %d headers but the whole encoding is %d bytes", count, len(b))
	}
	if count > 0 {
		s.Headers = make([]HeaderSpan, 0, count)
	}
	for i := uint64(0); i < count; i++ {
		name, err := d.span(fmt.Sprintf("header %d name", i))
		if err != nil {
			return MessageShape{}, err
		}
		value, err := d.span(fmt.Sprintf("header %d value", i))
		if err != nil {
			return MessageShape{}, err
		}
		s.Headers = append(s.Headers, HeaderSpan{Name: name, Value: value})
	}
	if d.pos != len(b) {
		return MessageShape{}, fmt.Errorf("shape has %d trailing bytes after a complete decode", len(b)-d.pos)
	}
	return s, nil
}

type decoder struct {
	buf []byte
	pos int
}

func (d *decoder) uvarint(what string) (uint64, error) {
	v, n := binary.Uvarint(d.buf[d.pos:])
	if n <= 0 {
		return 0, fmt.Errorf("shape is truncated at %s (offset %d of %d)", what, d.pos, len(d.buf))
	}
	d.pos += n
	return v, nil
}

func (d *decoder) span(what string) (Span, error) {
	offset, err := d.uvarint(what + " offset")
	if err != nil {
		return Span{}, err
	}
	length, err := d.uvarint(what + " length")
	if err != nil {
		return Span{}, err
	}
	return Span{Offset: int(offset), Len: int(length)}, nil
}
