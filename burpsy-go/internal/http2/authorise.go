package http2

import (
	"fmt"
	"strings"
)

// Frame-program authorisation: whether the engagement scope can make a sound decision about where a
// program's bytes will actually go, and what those bytes ask for.
//
// # Why a program needs its own classifier (H2-03)
//
// Authorising a request is settled: render the bytes, read the request line, ask the scope about that
// host and that path (sender.AuthorisedSender). A frame program cannot be authorised that way, and
// frame.go and malformed.go have both said so from the start — this is the classifier they said did not
// exist.
//
// The obstacle is not that a program is malformed. It is that **a program can make the peer decode
// something we did not.** A HEADERS frame declaring 40 octets and carrying 60 hands the peer a
// 40-octet header block; the 20 octets we thought were part of it become the start of what the peer
// reads as the next frame header. So the `:path` we decoded is not the `:path` the peer decodes, and
// authorising ours authorises a request that will never be made while the one that *will* be made goes
// unexamined. Every construct this file refuses has that same shape: our decode and the peer's part
// company, so a per-path scope decision is a decision about the wrong request.
//
// That is why the refusal is by construct and never "malformed, refused". An operator doing smuggling
// research needs to know that what stopped them is the undecidability itself and not a bug they can
// work around — and, just as importantly, needs to know that the *many* illegal programs which are
// still perfectly decidable do send.
//
// # What is emphatically not refused
//
// Most of malformed.go's violations are authorisable. An even client-initiated stream id, stream 0 on a
// HEADERS, a set reserved bit, a PUSH_PROMISE from a client, a SETTINGS with a bad length, a frame on a
// closed stream, a missing connection preface: every one of those is a rule broken on purpose, and none
// of them changes which octets the peer reads as the header block. The peer may well answer with
// GOAWAY and drop the connection — a peer that rejects our bytes has not been sent a *different*
// request, so scope has lost nothing. Refusing those would turn this classifier into a spec-compliance
// gate, which is the opposite of what burpsy is for.
//
// # Why there is no operator override
//
// There is deliberately no "I know what I am doing" flag, and the reason is not paternalism. HARD-03's
// property is that scope is not waivable by the caller: every egress goes through
// sender.AuthorisedSender's gate and the gate reads the bytes, not the caller's intent. An override
// here would not be a waiver of a *rule* — it would be a waiver of the tool's ability to *know* the
// answer. The refusals below are cases where nobody, including the operator, can say which request the
// peer will see; a flag saying "send it anyway" is a flag saying "authorise a request neither of us can
// name", which is exactly the state HARD-03 exists to make impossible. An operator who needs to send
// an undecidable program against a target has a decidable way to get the same coverage: pin the
// engagement scope to that authority so the host-level decision is the only one available, and send a
// program whose blocks decode (VerdictConnectionOnly, below, is that path).
//
// # What this classifier does not check, and why
//
// Stated because a verdict that looks exhaustive and is not would be worse than no verdict:
//
//   - **The peer's SETTINGS_HEADER_TABLE_SIZE.** Blocks are decoded against RFC 7541's 4096-octet
//     default, because a program is built offline and the peer's own SETTINGS have not been received.
//     A peer advertising a smaller table would evict entries our decode kept, so a program that indexes
//     a dynamic entry near the end of a large table could decode differently there. Programs this
//     package's Encoder produces stay far below that in practice, and checking it properly would mean
//     handshaking before classifying — which would put a connection *before* the authorisation
//     decision, in the wrong order.
//   - **Whether the peer will accept the program at all.** GOAWAY, RST_STREAM and connection errors are
//     outcomes, not authorisation questions. Audit names the rules; this file names only decidability.
//   - **HPACK the peer decodes differently for its own reasons** — a peer with a broken decoder. Nothing
//     can model that, and the program's own octets are what scope is asked about.
//   - **Response frames.** A program's replies are returned as octets and parsed with ReadFrames; no
//     authorisation question arises on the way in.
//   - **Field validity beyond authorisability** (§8.3): an uppercase field name, a connection-specific
//     header, a missing `:method`. Those make a request the peer will reject, not a request whose
//     destination is unknown, so they pass — the deliberate-malformation path is allowed to be
//     malformed.
//
// # Divergence from Rust
//
// crates/http2 has the same gap for the same reason and no equivalent of this file yet, so there is no
// upstream to be faithful to. The shapes follow the two local conventions instead: a Kind plus the union
// of per-variant fields (core.CorruptRecord, malformed.Violation), and a total switch rather than a map
// lookup wherever the set of cases is closed.

// RefusalKind names the construct that makes a program's effect on the peer un-inferable from our own
// decode.
type RefusalKind int

const (
	// RefusalDishonestLength is a length field that disagrees with the payload written. The peer frames
	// by the field, so from this frame on it reads a different byte stream from the one we described —
	// including different header blocks.
	RefusalDishonestLength RefusalKind = iota
	// RefusalPayloadExceedsLengthField is a payload longer than 24 bits can describe, so the header
	// carries MaxFramePayload and the peer stops short of the octets we wrote. Same consequence as a
	// dishonest length, reached without anyone lying on purpose.
	RefusalPayloadExceedsLengthField
	// RefusalUnterminatedHeaderBlock is a header block that never gets END_HEADERS. The peer holds the
	// block open waiting for a CONTINUATION that never comes, so it decodes nothing at all — there is no
	// request for scope to have an opinion about, and the fragment we decoded is not one.
	RefusalUnterminatedHeaderBlock
	// RefusalFrameInterleavedInHeaderBlock is a frame other than CONTINUATION inside an open block
	// (§6.2). The peer treats the block as broken and the interleaved frame's octets as part of nothing
	// we can predict.
	RefusalFrameInterleavedInHeaderBlock
	// RefusalContinuationWithNothingToContinue is a CONTINUATION with no open block before it. Its
	// fragment prepends to whatever the peer thinks is open, which is not what we decoded it against.
	RefusalContinuationWithNothingToContinue
	// RefusalContinuationOnAnotherStream is a CONTINUATION naming a different stream from the block it
	// continues. Which block the peer appends it to is undefined, so which stream's request carries these
	// fields is undefined too.
	RefusalContinuationOnAnotherStream
	// RefusalPaddingRunsPastPayload is a PADDED frame whose pad length is the whole payload or more, so
	// where the header-block fragment ends — or whether one exists — depends on arithmetic the peer will
	// do differently.
	RefusalPaddingRunsPastPayload
	// RefusalHeaderBlockDoesNotDecode is a header block this package's HPACK decoder cannot decode: a
	// bad index, a string length overrunning the block, the Huffman seam. This is where a hand-written
	// raw header-block fragment lands. Not "invalid HPACK is banned" — a fragment that *does* decode is
	// authorisable however it was built — but a block we cannot read is a block whose `:path` we cannot
	// check, and the peer will read something.
	RefusalHeaderBlockDoesNotDecode
	// RefusalNoPathPseudoHeader is a block that decodes and contains no `:path`. The engagement scope is
	// path-scoped, so there is nothing for it to decide; unlike a missing `:authority`, which the dialled
	// connection answers, nothing supplies a path.
	RefusalNoPathPseudoHeader
	// RefusalDuplicatePseudoHeader is a block carrying the same pseudo-header twice. Authorising one of
	// two `:path` values means choosing which one the peer means, and that choice is exactly the
	// ambiguity a smuggling probe is built out of. Detail names the field.
	RefusalDuplicatePseudoHeader
	// RefusalUnauthorisablePseudoHeader is a `:method`, `:authority` or `:path` carrying an octet that
	// would change how the authorisation request line itself reads — a space, a tab, CR, LF, NUL. The
	// scope gate reads a request line; a path with a space in it would be authorised up to the space and
	// sent whole. Detail names the field and what is in it.
	RefusalUnauthorisablePseudoHeader
)

// RefusalKindAll is every kind, in the order Authorise tests them: framing first, then block structure,
// then the decoded fields. A caller iterating this sees them in the order the code decides them.
var RefusalKindAll = [11]RefusalKind{
	RefusalDishonestLength,
	RefusalPayloadExceedsLengthField,
	RefusalUnterminatedHeaderBlock,
	RefusalFrameInterleavedInHeaderBlock,
	RefusalContinuationWithNothingToContinue,
	RefusalContinuationOnAnotherStream,
	RefusalPaddingRunsPastPayload,
	RefusalHeaderBlockDoesNotDecode,
	RefusalNoPathPseudoHeader,
	RefusalDuplicatePseudoHeader,
	RefusalUnauthorisablePseudoHeader,
}

// Why says what makes this construct undecidable, in the terms an operator needs: not that it is
// illegal — most of what this package emits is — but that it puts our decode and the peer's out of step.
func (k RefusalKind) Why() string {
	switch k {
	case RefusalDishonestLength:
		return "the peer frames by the declared length, so from this frame on it reads a different byte stream than the one we decoded"
	case RefusalPayloadExceedsLengthField:
		return "the length field cannot describe this payload, so the peer stops short of the octets written and reads the rest as something else"
	case RefusalUnterminatedHeaderBlock:
		return "the peer keeps the block open waiting for a CONTINUATION that never arrives, so it decodes no request at all"
	case RefusalFrameInterleavedInHeaderBlock:
		return "a frame inside an open header block breaks the block for the peer, so what it decodes is not what we did"
	case RefusalContinuationWithNothingToContinue:
		return "the fragment continues whatever block the peer believes is open, which is not the block we decoded it against"
	case RefusalContinuationOnAnotherStream:
		return "which block the peer appends this fragment to is undefined, so which request carries these fields is undefined"
	case RefusalPaddingRunsPastPayload:
		return "where the header-block fragment ends depends on padding arithmetic the peer will do differently"
	case RefusalHeaderBlockDoesNotDecode:
		return "this block cannot be decoded here, so its :path cannot be checked, and the peer will read something from it regardless"
	case RefusalNoPathPseudoHeader:
		return "the engagement scope is path-scoped and this block names no path, so there is nothing for it to decide"
	case RefusalDuplicatePseudoHeader:
		return "authorising one of two values means choosing which one the peer means, which is the ambiguity the probe is made of"
	case RefusalUnauthorisablePseudoHeader:
		return "this value would change how the authorisation request line reads, so the gate would check something other than what is sent"
	}
	return "unrecognised refusal"
}

// Refusal is one construct that makes a program unauthorisable.
//
// Only the fields its Kind names are populated; the rest are zero. Same shape and same reason as
// Violation — see malformed.go's divergence note — so a Kind that names no frame reads as frame 0 and
// String never prints a field its Kind does not name.
type Refusal struct {
	Kind RefusalKind
	// Frame is set for every Kind except RefusalUnterminatedHeaderBlock, which is program-level.
	Frame int
	// Declared is the length the peer will act on — the 24 bits actually written — and Actual the payload
	// written. Both are set for RefusalDishonestLength; Actual alone matters for
	// RefusalPayloadExceedsLengthField, where no honest value exists.
	Declared uint32
	Actual   int
	// Stream is set for the stream-scoped kinds.
	Stream uint32
	// Expected, Found are set for RefusalContinuationOnAnotherStream.
	Expected, Found uint32
	// BlockOpenedAt is set for RefusalFrameInterleavedInHeaderBlock, RefusalUnterminatedHeaderBlock and
	// the block-scoped field kinds: the frame that opened the block being talked about.
	BlockOpenedAt int
	// Detail names the field, the value or the decode fault, for the Kinds whose Why refers to one.
	Detail string
}

// String renders the refusal as a sentence an operator can act on: what was found, then why it cannot be
// authorised.
func (r Refusal) String() string {
	switch r.Kind {
	case RefusalDishonestLength:
		return fmt.Sprintf("frame %d declares %d octets and writes %d: %s",
			r.Frame, r.Declared, r.Actual, r.Kind.Why())
	case RefusalPayloadExceedsLengthField:
		return fmt.Sprintf("frame %d writes %d octets, more than a 24-bit length can describe: %s",
			r.Frame, r.Actual, r.Kind.Why())
	case RefusalUnterminatedHeaderBlock:
		return fmt.Sprintf("the header block opened at frame %d on stream %d is never terminated: %s",
			r.BlockOpenedAt, r.Stream, r.Kind.Why())
	case RefusalFrameInterleavedInHeaderBlock:
		return fmt.Sprintf("frame %d is inside the header block opened at frame %d: %s",
			r.Frame, r.BlockOpenedAt, r.Kind.Why())
	case RefusalContinuationWithNothingToContinue:
		return fmt.Sprintf("frame %d is a CONTINUATION with no open header block before it: %s",
			r.Frame, r.Kind.Why())
	case RefusalContinuationOnAnotherStream:
		return fmt.Sprintf("frame %d continues stream %d's block while naming stream %d: %s",
			r.Frame, r.Expected, r.Found, r.Kind.Why())
	case RefusalPaddingRunsPastPayload:
		return fmt.Sprintf("frame %d is PADDED and its pad length does not fit its payload: %s",
			r.Frame, r.Kind.Why())
	case RefusalHeaderBlockDoesNotDecode:
		return fmt.Sprintf("the header block opened at frame %d does not decode (%s): %s",
			r.BlockOpenedAt, r.Detail, r.Kind.Why())
	case RefusalNoPathPseudoHeader:
		return fmt.Sprintf("the header block opened at frame %d names no :path: %s",
			r.BlockOpenedAt, r.Kind.Why())
	case RefusalDuplicatePseudoHeader:
		return fmt.Sprintf("the header block opened at frame %d carries %s twice: %s",
			r.BlockOpenedAt, r.Detail, r.Kind.Why())
	case RefusalUnauthorisablePseudoHeader:
		return fmt.Sprintf("the header block opened at frame %d carries %s: %s",
			r.BlockOpenedAt, r.Detail, r.Kind.Why())
	}
	return fmt.Sprintf("frame %d cannot be authorised for a reason this build cannot name (kind %d)",
		r.Frame, r.Kind)
}

// ProgramRequest is one request a program's header blocks address, as the peer will read it.
//
// Authority may be empty, which means the request addresses whatever authority the connection was
// dialled to: an h2 request without `:authority` is malformed (§8.3.1) and the peer will reject it, but
// the octets still go exactly one place, and that place is decidable. Path never is — a block with no
// path is refused, because nothing supplies one.
type ProgramRequest struct {
	// Frame is the index of the frame that opened this block, so a refusal or an authorisation can be
	// shown against it.
	Frame  int
	Stream uint32
	Method string
	Scheme string
	// Authority is the `:authority` the block names, empty when it names none.
	Authority string
	Path      string
	// Fields is the whole decoded list in block order, pseudo-headers included, for a caller that wants
	// to show what it authorised rather than a summary of it.
	Fields []HeaderField
}

// ProgramVerdict is what kind of scope decision a program admits.
type ProgramVerdict int

const (
	// VerdictAuthorisable means every header block decodes, every request it addresses is named, and
	// nothing in the program makes the peer's decode differ from ours. The caller checks each
	// ProgramRequest against the scope and sends if they all pass.
	VerdictAuthorisable ProgramVerdict = iota
	// VerdictConnectionOnly means the program decodes but addresses no request — a SETTINGS flood, a PING
	// storm, a bare preface. The only scope question available is the host-level one: does the engagement
	// admit this authority at all. Kept apart from VerdictAuthorisable rather than treated as trivially
	// authorisable, because "every addressed request is in scope" is vacuously true of a program that
	// addresses none, and a vacuous yes is how a gate ends up authorising something nobody looked at.
	VerdictConnectionOnly
	// VerdictUndecidable means at least one construct puts our decode and the peer's out of step.
	// Refusals names each one.
	VerdictUndecidable
)

func (v ProgramVerdict) String() string {
	switch v {
	case VerdictAuthorisable:
		return "authorisable per request"
	case VerdictConnectionOnly:
		return "authorisable at host level only"
	case VerdictUndecidable:
		return "not authorisable"
	}
	return "unrecognised verdict"
}

// Authorisation is what Authorise concluded about one program.
type Authorisation struct {
	Verdict ProgramVerdict
	// Requests is every request the program addresses, in the order the blocks appear. Empty for
	// VerdictConnectionOnly and for VerdictUndecidable.
	Requests []ProgramRequest
	// Refusals is why the program is undecidable, one entry per construct. Non-empty exactly when
	// Verdict is VerdictUndecidable.
	Refusals []Refusal
}

// Explain renders the verdict and its reasons as lines an operator can read, so a refusal reaching a UI
// or a log names its constructs rather than arriving as "malformed".
func (a Authorisation) Explain() string {
	var b strings.Builder
	b.WriteString(a.Verdict.String())
	for _, r := range a.Refusals {
		b.WriteString("\n  - ")
		b.WriteString(r.String())
	}
	return b.String()
}

// hpackDefaultTableSize is RFC 7541's SETTINGS_HEADER_TABLE_SIZE default, which is what a peer's decoder
// uses until its own SETTINGS say otherwise. See the header on why a program built offline cannot know
// better.
const hpackDefaultTableSize = 4096

// Authorise classifies a program: can the engagement scope make a sound decision about where these
// bytes will go and what they ask for?
//
// It authorises nothing itself and holds no scope handle — that is sender.AuthorisedSender's job, on the
// requests this returns. Keeping the two apart is deliberate: this file decides what is *knowable*, and
// exactly one place in the tool decides what is *permitted*.
func Authorise(program H2FrameProgram) Authorisation {
	if refusals := framingRefusals(program); len(refusals) > 0 {
		// Returned before any decode. Once a length lies, the octets a peer reads as frame headers are not
		// the ones we wrote, so decoding our own framing would produce header blocks nobody will ever
		// see — a report about them would be confident and wrong.
		return Authorisation{Verdict: VerdictUndecidable, Refusals: refusals}
	}
	blocks, refusals := headerBlocks(program)
	if len(refusals) > 0 {
		return Authorisation{Verdict: VerdictUndecidable, Refusals: refusals}
	}

	// One decoder for the whole program, in frame order: a dynamic table is per-connection state, and a
	// program opens one connection. A fresh decoder per block would resolve index 62 against an empty
	// table while the peer resolves it against whatever the previous block inserted.
	decoder := NewDecoder(hpackDefaultTableSize)
	var requests []ProgramRequest
	for _, blk := range blocks {
		fields, err := decoder.Decode(blk.fragment)
		if err != nil {
			// Stops here rather than carrying on. After a failed decode the dynamic table's state is
			// unknown, so every later block is unknowable too, and reporting them as separate faults would
			// be inventing findings out of one.
			return Authorisation{Verdict: VerdictUndecidable, Refusals: []Refusal{{
				Kind:          RefusalHeaderBlockDoesNotDecode,
				Frame:         blk.openedAt,
				BlockOpenedAt: blk.openedAt,
				Stream:        blk.stream,
				Detail:        err.Error(),
			}}}
		}
		req, blockRefusals := addressedRequest(blk, fields)
		if len(blockRefusals) > 0 {
			return Authorisation{Verdict: VerdictUndecidable, Refusals: blockRefusals}
		}
		requests = append(requests, req)
	}

	if len(requests) == 0 {
		return Authorisation{Verdict: VerdictConnectionOnly}
	}
	return Authorisation{Verdict: VerdictAuthorisable, Requests: requests}
}

// framingRefusals reports every frame whose length field will make the peer read a different byte stream
// from the one written. Checked over the whole program before anything else, because one such frame
// invalidates every boundary after it.
//
// The comparison is against the length the peer will *act on* — the 24 bits actually written, after the
// truncation FrameHeader.Encode forces — and not against what the caller asked for. That distinction has
// two consequences, both deliberate, and it is the same "judge the length in the peer's terms" rule
// malformed.go's header sets out:
//
//   - A DeclaredLen above 24 bits whose low bits happen to equal the payload's own length is *decidable*.
//     The peer reads exactly the octets we wrote, so its decode is ours; Audit reports the overflow as a
//     violation, and this file has no reason to refuse it. Comparing against the requested value would
//     refuse a program that works, which is the over-strict direction this classifier exists to avoid.
//   - A DeclaredLen that equals the payload's length while both exceed 24 bits is *not* decidable, even
//     though nobody lied: the field carries the truncated value, so the peer stops short. Comparing only
//     LengthIsDishonest would have missed exactly that case.
func framingRefusals(program H2FrameProgram) []Refusal {
	var out []Refusal
	for i := range program.Frames {
		spec := program.Frames[i]
		// What a peer frames by: the header's 24 bits, after any truncation the field forces.
		written := spec.Header().Len & MaxFramePayload
		if uint64(written) == uint64(len(spec.Payload)) {
			continue
		}
		kind := RefusalPayloadExceedsLengthField
		if spec.DeclaredLen != nil {
			kind = RefusalDishonestLength
		}
		out = append(out, Refusal{
			Kind: kind,
			// The value the peer will act on, which is what makes its decode differ from ours; the value
			// requested is Audit's subject, not this file's.
			Declared: written,
			Frame:    i,
			Actual:   len(spec.Payload),
			Stream:   spec.StreamID & ^StreamIDReservedBit,
		})
	}
	return out
}

// headerBlock is one complete header block: where it started, whose stream it is, and the concatenated
// fragment the peer will decode.
type headerBlock struct {
	openedAt int
	stream   uint32
	fragment []byte
}

// headerBlocks walks the program the way a peer does, assembling each header block from its HEADERS or
// PUSH_PROMISE frame and the CONTINUATIONs that follow, and reports every construct that makes that walk
// diverge from the peer's.
//
// PUSH_PROMISE blocks are assembled too, even though a client sending one is a §8.4 violation Audit
// already reports. The promised request's `:path` is a path this program puts on the wire, and every
// path it puts on the wire is a path the scope must have agreed to.
func headerBlocks(program H2FrameProgram) ([]headerBlock, []Refusal) {
	var blocks []headerBlock
	var refusals []Refusal
	open := false
	var current headerBlock

	for i := range program.Frames {
		spec := program.Frames[i]
		stream := spec.StreamID & ^StreamIDReservedBit

		if open {
			if spec.Type != TypeContinuation {
				refusals = append(refusals, Refusal{
					Kind:          RefusalFrameInterleavedInHeaderBlock,
					Frame:         i,
					BlockOpenedAt: current.openedAt,
					Stream:        current.stream,
				})
				// Keeps walking so a program with several such frames names them all, but the block itself
				// is already lost: nothing else about it can be trusted.
				continue
			}
			if stream != current.stream {
				refusals = append(refusals, Refusal{
					Kind:     RefusalContinuationOnAnotherStream,
					Frame:    i,
					Expected: current.stream,
					Found:    stream,
				})
				continue
			}
			current.fragment = append(current.fragment, spec.Payload...)
			if spec.Flags&FlagEndHeaders != 0 {
				blocks = append(blocks, current)
				open, current = false, headerBlock{}
			}
			continue
		}

		switch spec.Type {
		case TypeContinuation:
			refusals = append(refusals, Refusal{
				Kind:   RefusalContinuationWithNothingToContinue,
				Frame:  i,
				Stream: stream,
			})
		case TypeHeaders, TypePushPromise:
			fragment, ok := blockFragment(spec)
			if !ok {
				refusals = append(refusals, Refusal{
					Kind:   RefusalPaddingRunsPastPayload,
					Frame:  i,
					Stream: stream,
				})
				continue
			}
			block := headerBlock{openedAt: i, stream: stream, fragment: fragment}
			if spec.Flags&FlagEndHeaders != 0 {
				blocks = append(blocks, block)
				continue
			}
			open, current = true, block
		}
	}

	if open {
		refusals = append(refusals, Refusal{
			Kind:          RefusalUnterminatedHeaderBlock,
			BlockOpenedAt: current.openedAt,
			Stream:        current.stream,
		})
	}
	return blocks, refusals
}

// blockFragment cuts the header-block fragment out of a HEADERS or PUSH_PROMISE payload, stripping the
// pad-length octet, the priority fields, the promised stream id and the trailing padding — the layout
// §6.2 and §6.6 define.
//
// Reports false when the padding does not fit, which is the one case where the fragment's extent is a
// matter of arithmetic the peer will do differently. A priority or promised-id prefix longer than the
// payload leaves an empty fragment rather than a refusal: the peer reads an empty block there too, and
// an empty block decodes to an empty field list, which is a decidable (and pathless) request.
func blockFragment(spec FrameSpec) ([]byte, bool) {
	payload := spec.Payload
	if spec.Flags&FlagPadded != 0 {
		if len(payload) == 0 {
			// PADDED with no octet to carry the pad length: the peer has nothing to read the length from.
			return nil, false
		}
		pad := int(payload[0])
		payload = payload[1:]
		if pad > len(payload) {
			return nil, false
		}
		payload = payload[:len(payload)-pad]
	}
	prefix := 0
	if spec.Type == TypeHeaders && spec.Flags&FlagPriority != 0 {
		prefix = 5
	}
	if spec.Type == TypePushPromise {
		prefix = 4
	}
	if prefix > len(payload) {
		return nil, true
	}
	return payload[prefix:], true
}

// addressedRequest reads one decoded block's pseudo-headers into the request it addresses, refusing the
// values a scope decision cannot be built on.
func addressedRequest(blk headerBlock, fields []HeaderField) (ProgramRequest, []Refusal) {
	req := ProgramRequest{Frame: blk.openedAt, Stream: blk.stream, Fields: fields}
	seen := map[string]bool{}
	for _, f := range fields {
		name := string(f.Name)
		if !strings.HasPrefix(name, ":") {
			continue
		}
		switch name {
		case ":method", ":scheme", ":authority", ":path":
			if seen[name] {
				return ProgramRequest{}, []Refusal{{
					Kind:          RefusalDuplicatePseudoHeader,
					Frame:         blk.openedAt,
					BlockOpenedAt: blk.openedAt,
					Stream:        blk.stream,
					Detail:        name,
				}}
			}
			seen[name] = true
		default:
			// An unknown pseudo-header is a §8.3 violation the peer will reject, and it addresses nothing,
			// so it is not this classifier's business.
			continue
		}
		value := string(f.Value)
		if bad := unauthorisableOctet(value); bad != "" {
			return ProgramRequest{}, []Refusal{{
				Kind:          RefusalUnauthorisablePseudoHeader,
				Frame:         blk.openedAt,
				BlockOpenedAt: blk.openedAt,
				Stream:        blk.stream,
				Detail:        fmt.Sprintf("%s with %s in it", name, bad),
			}}
		}
		switch name {
		case ":method":
			req.Method = value
		case ":scheme":
			req.Scheme = value
		case ":authority":
			req.Authority = value
		case ":path":
			req.Path = value
		}
	}
	if req.Path == "" {
		return ProgramRequest{}, []Refusal{{
			Kind:          RefusalNoPathPseudoHeader,
			Frame:         blk.openedAt,
			BlockOpenedAt: blk.openedAt,
			Stream:        blk.stream,
		}}
	}
	return req, nil
}

// unauthorisableOctet names the first octet in a pseudo-header value that would change how the
// authorisation request line reads, and returns "" when there is none.
//
// A space is the dangerous one and the reason this check exists: core.Scope's gate reads the second
// space-separated token of a request line, so a `:path` of "/a /b" would be authorised as "/a" and sent
// as "/a /b". CR, LF and NUL are here for the same class of reason one level up — they end or split the
// line the gate reads.
func unauthorisableOctet(value string) string {
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case ' ':
			return "a space"
		case '\t':
			return "a tab"
		case '\r':
			return "a carriage return"
		case '\n':
			return "a line feed"
		case 0:
			return "a NUL"
		}
	}
	return ""
}
