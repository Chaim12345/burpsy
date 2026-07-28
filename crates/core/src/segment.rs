//! Segmented, sealed, mmap-backed storage for captured traffic.
//!
//! Two decisions shape this file, and both look like implementation detail until you try the
//! obvious alternative.
//!
//! **A segment is always in exactly one of two states.** Either it is being written to through a
//! buffered `File` and is never mapped, or it is mapped read-only and is never written again. There
//! is no state where both are true. This is not a performance choice: a mapping that gets remapped
//! or grown while `Bytes` slices into it are still outstanding leaves those slices pointing at
//! memory the kernel has moved, which is a dangling-pointer bug, not a stale read. Keeping the two
//! states disjoint is what makes [`SegmentLog::resolve`] sound for a sealed segment.
//!
//! **The segment target is a target, not a cap.** A single captured message larger than the target
//! is written into its own oversized segment and sealed immediately — never rejected, never
//! truncated, never split across two files. Append-only-log precedent (Kafka's
//! `message.max.bytes` < `log.segment.bytes` rule) is to refuse the oversized record, and that
//! answer is wrong here: refusing to store a large response would silently violate the
//! capture-everything premise this store exists to serve, for no correctness benefit. mmap does not
//! require uniform segment sizes — it requires that a live mapping is never remapped, which an
//! occasionally larger, still-immutable-once-sealed segment satisfies exactly as well.
//!
//! # The checksum is not a security control
//!
//! Every record carries a CRC32 over its payload, and [`scan_segment_file`] verifies it. That
//! catches torn writes, bit rot, and truncation — accidental corruption. It is **not a
//! cryptographic integrity or tamper-evidence guarantee** and must never be described as one in a
//! doc comment, an error string, or any operator-facing text. An adversary with write access to the
//! capture directory can recompute a CRC as easily as we can.

use crate::{Direction, MsgId};
use anyhow::{Context, bail};
use bytes::Bytes;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Magic bytes at the start of every segment file.
pub const SEGMENT_MAGIC: [u8; 8] = *b"BURPSYSG";

/// On-disk format version.
///
/// This lives in the **segment file** header, never in the per-record header — one byte per file
/// rather than one per record. It is cheap insurance against the one thing that is genuinely
/// expensive to retrofit. Phase 1 deliberately ships no migration-between-format-versions story:
/// a file whose version we do not recognise is refused by name, not converted.
pub const SEGMENT_FORMAT_VERSION: u8 = 1;

/// Segment file header: magic(8) + version(1) + reserved(7), the reserved bytes written as zero.
pub const SEGMENT_FILE_HEADER_LEN: usize = 16;

/// Per-record header: len(4) + msg_id(8) + direction(1) + crc32(4).
pub const RECORD_HEADER_LEN: usize = 17;

/// Default rotation target. A target, not a cap — see the module header.
///
/// 64 MiB bounds the *active* segment, whose payload handles are held in RAM until it seals, so
/// this number is a memory ceiling on work in flight rather than merely a rotation cadence. Kafka's
/// 1 GiB default is sized for a case where segment bytes are not held resident by the writer the
/// way they are here; it is the wrong number to import, useful only as an order-of-magnitude check
/// that tens of MiB is a sane regime for a segmented log.
pub const DEFAULT_SEGMENT_TARGET_BYTES: usize = 64 * 1024 * 1024;

/// Where one record's payload lives. The header sits in the `RECORD_HEADER_LEN` bytes immediately
/// before `offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Location {
    pub segment: u32,
    pub offset: usize,
    pub len: usize,
}

/// One record's on-disk header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub len: u32,
    pub msg_id: MsgId,
    pub direction: Direction,
    pub crc32: u32,
}

impl RecordHeader {
    /// Little-endian, in field order: len, msg_id, direction, crc32.
    pub fn encode(&self) -> [u8; RECORD_HEADER_LEN] {
        let mut out = [0u8; RECORD_HEADER_LEN];
        out[0..4].copy_from_slice(&self.len.to_le_bytes());
        out[4..12].copy_from_slice(&self.msg_id.0.to_le_bytes());
        out[12] = match self.direction {
            Direction::Request => 0,
            Direction::Response => 1,
        };
        out[13..17].copy_from_slice(&self.crc32.to_le_bytes());
        out
    }

    /// Decode a header. `at` is the byte offset it was read from, carried so every failure can name
    /// *where* it was found rather than only what was wrong with it.
    pub fn decode(at: usize, bytes: &[u8]) -> Result<Self, CorruptRecord> {
        if bytes.len() < RECORD_HEADER_LEN {
            return Err(CorruptRecord::ShortHeader {
                at,
                need: RECORD_HEADER_LEN,
                have: bytes.len(),
            });
        }
        let len = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
        let msg_id = MsgId(u64::from_le_bytes(
            bytes[4..12].try_into().expect("8 bytes"),
        ));
        // An unrecognised direction byte is corruption, not something to default. Defaulting to
        // Request would turn a damaged file into a plausible-looking one.
        let direction = match bytes[12] {
            0 => Direction::Request,
            1 => Direction::Response,
            byte => return Err(CorruptRecord::UnknownDirection { at, byte }),
        };
        let crc32 = u32::from_le_bytes(bytes[13..17].try_into().expect("4 bytes"));
        Ok(Self {
            len,
            msg_id,
            direction,
            crc32,
        })
    }
}

/// A fault found in a segment file, always carrying the byte offset it was found at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorruptRecord {
    ShortHeader {
        at: usize,
        need: usize,
        have: usize,
    },
    UnknownDirection {
        at: usize,
        byte: u8,
    },
    LengthOverrunsSegment {
        at: usize,
        declared: usize,
        segment_len: usize,
    },
    ChecksumMismatch {
        at: usize,
        id: MsgId,
        stored: u32,
        recomputed: u32,
    },
}

impl CorruptRecord {
    /// The byte offset the fault was found at, so callers can report position uniformly without
    /// matching on the variant.
    pub fn at(&self) -> usize {
        match self {
            CorruptRecord::ShortHeader { at, .. }
            | CorruptRecord::UnknownDirection { at, .. }
            | CorruptRecord::LengthOverrunsSegment { at, .. }
            | CorruptRecord::ChecksumMismatch { at, .. } => *at,
        }
    }
}

impl std::fmt::Display for CorruptRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Each arm says what the failure means for an operator, not which field disagreed.
        match self {
            CorruptRecord::ShortHeader { at, need, have } => write!(
                f,
                "record header at byte {at} needs {need} bytes but only {have} remain — the segment \
                 ends mid-header, so it was truncated"
            ),
            CorruptRecord::UnknownDirection { at, byte } => write!(
                f,
                "record header at byte {at} carries direction byte {byte}, which is neither request \
                 (0) nor response (1) — the header is corrupt"
            ),
            CorruptRecord::LengthOverrunsSegment {
                at,
                declared,
                segment_len,
            } => write!(
                f,
                "record header at byte {at} declares {declared} bytes of payload but the segment is \
                 only {segment_len} long — the header is corrupt or the file was truncated"
            ),
            CorruptRecord::ChecksumMismatch {
                at,
                id,
                stored,
                recomputed,
            } => write!(
                f,
                "message {} at byte {at} does not match the checksum written with it (stored \
                 {stored:#010x}, recomputed {recomputed:#010x}) — its bytes changed after they were \
                 written",
                id.0
            ),
        }
    }
}

impl std::error::Error for CorruptRecord {}

/// The result of walking one segment file end to end.
///
/// `corruption` is `Some` for the *first* fault found, and `records` still carries everything read
/// before it. Reporting rather than erroring out is what lets an operator-facing verify emit a
/// per-record verdict instead of a bare pass/fail.
#[derive(Debug, Clone)]
pub struct SegmentScan {
    pub index: u32,
    pub records: Vec<(RecordHeader, Location)>,
    pub corruption: Option<CorruptRecord>,
}

/// `"segment-000000.log"` — the name a segment takes once sealed.
pub fn segment_file_name(index: u32) -> String {
    format!("segment-{index:06}.log")
}

/// The name a segment carries while it is still being written.
///
/// Sealing renames this to [`segment_file_name`], which is atomic on one filesystem — that rename
/// is what makes a sealed segment appear all at once rather than as a partially-written file. Only
/// this process ever creates, renames, or removes files under a capture directory; that exclusive
/// ownership is the prevention half of the truncation hazard the CRC scan detects.
fn tmp_file_name(index: u32) -> String {
    format!("{}.tmp", segment_file_name(index))
}

fn index_from_file_name(path: &Path) -> u32 {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("segment-"))
        .and_then(|n| n.split('.').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// One segment, in exactly one of its two states. See the module header for why these are disjoint.
#[derive(Debug)]
enum Segment {
    Active {
        index: u32,
        path: PathBuf,
        file: BufWriter<File>,
        /// Bytes written so far, including the file header and every record header. Equals the
        /// file's length once flushed, which is what makes it usable as a bound in `resolve`.
        len: usize,
        /// Payload handles for records in this segment, keyed by payload offset.
        ///
        /// Not a second copy of the bytes: the caller already owns each payload as a refcounted
        /// `Bytes`, so holding that handle keeps active-segment resolution zero-copy for one
        /// pointer per record. The total length held here is exactly the residency the segment
        /// target exists to bound. Cleared on seal, because a sealed segment resolves through its
        /// mapping instead.
        live: HashMap<usize, Bytes>,
    },
    Sealed {
        index: u32,
        path: PathBuf,
        len: usize,
        /// The whole file, mapped read-only and wrapped once.
        map: Bytes,
    },
}

impl Segment {
    fn index(&self) -> u32 {
        match self {
            Segment::Active { index, .. } | Segment::Sealed { index, .. } => *index,
        }
    }

    fn len(&self) -> usize {
        match self {
            Segment::Active { len, .. } | Segment::Sealed { len, .. } => *len,
        }
    }
}

/// An append-only log of captured payloads, split into sealed segments.
///
/// The public surface is deliberately small: append a payload and get a [`Location`], resolve a
/// `Location` back to bytes, and seal. Everything about files, mapping, and rotation is private.
#[derive(Debug)]
pub struct SegmentLog {
    dir: PathBuf,
    target_bytes: usize,
    /// Every segment, in index order. All but the last are `Sealed`; the last is `Active`.
    segments: Vec<Segment>,
}

impl SegmentLog {
    /// Open `dir` as a capture directory and start segment 0.
    ///
    /// Startup recovery is deliberately out of scope for this phase: `open` does **not** rescan
    /// existing sealed segments to rebuild an index. The self-describing record format exists so a
    /// later phase can, which is also why a directory that already holds a capture is refused
    /// rather than written over — without a recovery path, reusing it would destroy the prior
    /// capture.
    pub fn open(dir: &Path, target_bytes: usize) -> anyhow::Result<Self> {
        if target_bytes == 0 {
            bail!("segment target_bytes must be non-zero");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            // 0o700: a capture directory holds real traffic — session cookies, tokens, response
            // bodies. Other local users have no business reading it.
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true).mode(0o700);
            b.create(dir)
                .with_context(|| format!("creating capture directory {}", dir.display()))?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating capture directory {}", dir.display()))?;

        let mut existing = Vec::new();
        for entry in std::fs::read_dir(dir)
            .with_context(|| format!("reading capture directory {}", dir.display()))?
        {
            let path = entry?.path();
            let is_segment = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("segment-") && n.ends_with(".log"));
            if !is_segment {
                continue;
            }
            // Validate before complaining about reuse, so a foreign or future-version file is
            // reported as what it is rather than as "a previous capture".
            let mut head = [0u8; SEGMENT_FILE_HEADER_LEN];
            let mut f = File::open(&path)
                .with_context(|| format!("opening existing segment {}", path.display()))?;
            f.read_exact(&mut head)
                .with_context(|| format!("{} is too short to be a segment file", path.display()))?;
            if head[..8] != SEGMENT_MAGIC {
                bail!(
                    "{} is not a burpsy segment file (bad magic) — refusing to use this directory",
                    path.display()
                );
            }
            if head[8] != SEGMENT_FORMAT_VERSION {
                bail!(
                    "{} is segment format version {}, but this build understands version {} — \
                     refusing to use this directory",
                    path.display(),
                    head[8],
                    SEGMENT_FORMAT_VERSION
                );
            }
            existing.push(path);
        }
        if !existing.is_empty() {
            existing.sort();
            bail!(
                "{} already holds {} sealed segment(s) from a previous capture (first: {}); \
                 startup recovery is not implemented, so opening here would overwrite them — use \
                 an empty directory",
                dir.display(),
                existing.len(),
                existing[0].display()
            );
        }

        let active = Self::open_active(dir, 0)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            target_bytes,
            segments: vec![active],
        })
    }

    fn open_active(dir: &Path, index: u32) -> anyhow::Result<Segment> {
        let path = dir.join(tmp_file_name(index));
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .with_context(|| format!("creating segment {}", path.display()))?;
        let mut file = BufWriter::new(f);
        let mut head = [0u8; SEGMENT_FILE_HEADER_LEN];
        head[..8].copy_from_slice(&SEGMENT_MAGIC);
        head[8] = SEGMENT_FORMAT_VERSION;
        file.write_all(&head)
            .with_context(|| format!("writing segment header to {}", path.display()))?;
        Ok(Segment::Active {
            index,
            path,
            file,
            len: SEGMENT_FILE_HEADER_LEN,
            live: HashMap::new(),
        })
    }

    /// Append a payload and return where it lives.
    ///
    /// Rotation happens only at a completed-record boundary, never mid-write, which is what
    /// guarantees one message's bytes never span two segments.
    pub fn append(
        &mut self,
        id: MsgId,
        direction: Direction,
        payload: &Bytes,
    ) -> anyhow::Result<Location> {
        let payload_len = payload.len();
        let declared: u32 = payload_len.try_into().with_context(|| {
            format!("payload of {payload_len} bytes exceeds the u32 record length")
        })?;

        // Rotate first if this record would push an already-non-empty segment past the target. A
        // segment holding no records yet never rotates here, or an oversized message would land in
        // an empty segment only to rotate again immediately.
        {
            let active = self.active()?;
            if active.len() > SEGMENT_FILE_HEADER_LEN
                && active.len() + RECORD_HEADER_LEN + payload_len > self.target_bytes
            {
                self.seal_active()?;
                let next = self.next_index();
                let seg = Self::open_active(&self.dir, next)?;
                self.segments.push(seg);
            }
        }

        let crc32 = crc32fast::hash(payload);
        let header = RecordHeader {
            len: declared,
            msg_id: id,
            direction,
            crc32,
        };

        let (segment_index, payload_offset, record_total, overshoots_alone) = {
            let Some(Segment::Active {
                index,
                file,
                len,
                live,
                ..
            }) = self.segments.last_mut()
            else {
                bail!("no active segment to append to");
            };
            let payload_offset = *len + RECORD_HEADER_LEN;
            file.write_all(&header.encode())
                .context("writing record header")?;
            file.write_all(payload).context("writing record payload")?;
            live.insert(payload_offset, payload.clone());
            let record_total = RECORD_HEADER_LEN + payload_len;
            *len += record_total;
            let overshoots_alone = SEGMENT_FILE_HEADER_LEN + record_total > self.target_bytes;
            (*index, payload_offset, record_total, overshoots_alone)
        };
        let _ = record_total;

        // A message bigger than the whole target gets its own segment, sealed at once so it is
        // immutable immediately. This is the deliberate divergence from Kafka's refuse-oversized
        // rule — see the module header for why refusing would be the wrong answer here.
        if overshoots_alone {
            self.seal_active()?;
            let next = self.next_index();
            let seg = Self::open_active(&self.dir, next)?;
            self.segments.push(seg);
        }

        Ok(Location {
            segment: segment_index,
            offset: payload_offset,
            len: payload_len,
        })
    }

    /// Resolve a location back to its bytes, or `None` if it does not name a real record.
    ///
    /// Returns `None` rather than an empty `Bytes` on an out-of-bounds span, so a caller can tell
    /// "past the end" apart from "a genuinely zero-length payload".
    pub fn resolve(&self, loc: Location) -> Option<Bytes> {
        let seg = self.segment(loc.segment)?;
        let end = loc.offset.checked_add(loc.len)?;
        if end > seg.len() {
            return None;
        }
        match seg {
            Segment::Active { live, .. } => {
                // A length disagreement means the index and the log have desynchronised. Say
                // nothing rather than hand back bytes of the wrong length.
                live.get(&loc.offset)
                    .filter(|b| b.len() == loc.len)
                    .cloned()
            }
            Segment::Sealed { map, .. } => Some(map.slice(loc.offset..end)),
        }
    }

    /// The on-disk header for a record, so a caller can compare its stored checksum against a
    /// recomputation without rescanning the whole file.
    ///
    /// For a record in the active segment this reads from disk, so call [`Self::flush_active`]
    /// first. A location naming a segment that does not exist reports `ShortHeader` with `have: 0`
    /// — the error vocabulary here describes faults in a record, and an unknown segment has no
    /// better encoding in it.
    pub fn header_at(&self, loc: Location) -> Result<RecordHeader, CorruptRecord> {
        let short = |at: usize| CorruptRecord::ShortHeader {
            at,
            need: RECORD_HEADER_LEN,
            have: 0,
        };
        let header_at = match loc.offset.checked_sub(RECORD_HEADER_LEN) {
            Some(h) if h >= SEGMENT_FILE_HEADER_LEN => h,
            _ => return Err(short(loc.offset)),
        };
        let seg = self.segment(loc.segment).ok_or_else(|| short(header_at))?;
        match seg {
            Segment::Sealed { map, .. } => {
                if header_at + RECORD_HEADER_LEN > map.len() {
                    return Err(CorruptRecord::ShortHeader {
                        at: header_at,
                        need: RECORD_HEADER_LEN,
                        have: map.len().saturating_sub(header_at),
                    });
                }
                RecordHeader::decode(header_at, &map[header_at..header_at + RECORD_HEADER_LEN])
            }
            Segment::Active { path, .. } => {
                let mut buf = [0u8; RECORD_HEADER_LEN];
                let mut f = File::open(path).map_err(|_| short(header_at))?;
                f.seek(SeekFrom::Start(header_at as u64))
                    .map_err(|_| short(header_at))?;
                f.read_exact(&mut buf).map_err(|_| short(header_at))?;
                RecordHeader::decode(header_at, &buf)
            }
        }
    }

    /// Seal the active segment: fsync, rename, verify, then map once.
    ///
    /// **The order is the safety argument.** Reordering any two of these steps reintroduces one of
    /// the two hazards this whole design exists to avoid — either a segment that is mapped while
    /// still writable, or a segment whose bytes are trusted without ever having been checked.
    pub fn seal_active(&mut self) -> anyhow::Result<()> {
        if !matches!(self.segments.last(), Some(Segment::Active { .. })) {
            bail!("no active segment to seal");
        }
        let Some(Segment::Active {
            index,
            path,
            mut file,
            len,
            live,
        }) = self.segments.pop()
        else {
            unreachable!("checked immediately above");
        };
        // The payload handles go now: from here on this segment resolves through its mapping, and
        // holding them would defeat the memory bound sealing exists to restore.
        drop(live);

        // 1. Everything buffered reaches the file, and the file reaches the disk.
        file.flush().context("flushing segment before seal")?;
        file.get_ref()
            .sync_all()
            .context("fsyncing segment before seal")?;
        // 2. No write handle survives the rename.
        drop(file);
        // 3. Atomic on one filesystem: the sealed name appears complete or not at all.
        let sealed_path = self.dir.join(segment_file_name(index));
        std::fs::rename(&path, &sealed_path)
            .with_context(|| format!("sealing {} -> {}", path.display(), sealed_path.display()))?;
        // 4. Verify before trusting. A segment that fails its own scan is never mapped — the whole
        //    point is that success is not inferred from the absence of a crash.
        let scan = scan_segment_file(&sealed_path)?;
        if let Some(fault) = scan.corruption {
            bail!(
                "segment {index} failed its seal scan at byte {}: {fault}",
                fault.at()
            );
        }
        // 5. Map read-only.
        //
        //    SAFETY: soundness here rests on one precondition — only this process creates, renames,
        //    or removes files under the capture directory, and a sealed file is never written
        //    again, so the mapping cannot be invalidated underneath outstanding slices. The
        //    residual, stated honestly: an external process that truncates a sealed file can still
        //    fault this one on access. That is why the CRC scan above is the detection half; it is
        //    not prevented.
        let f = File::open(&sealed_path)
            .with_context(|| format!("reopening {} to map", sealed_path.display()))?;
        let map = unsafe { memmap2::Mmap::map(&f) }
            .with_context(|| format!("mapping {}", sealed_path.display()))?;
        // 6. Wrapped exactly once. `Mmap` is already `AsRef<[u8]> + Send + 'static`, so it needs no
        //    `Arc` around it — `Bytes` does the refcount-and-drop-on-last-clone bookkeeping.
        let map = Bytes::from_owner(map);
        debug_assert_eq!(
            map.len(),
            len,
            "sealed segment length disagrees with what was written"
        );
        let len = map.len();
        self.segments.push(Segment::Sealed {
            index,
            path: sealed_path,
            len,
            map,
        });
        Ok(())
    }

    /// Push buffered bytes to the file without sealing, so an on-disk read sees them.
    pub fn flush_active(&mut self) -> anyhow::Result<()> {
        if let Some(Segment::Active { file, .. }) = self.segments.last_mut() {
            file.flush().context("flushing active segment")?;
        }
        Ok(())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    pub fn sealed_count(&self) -> usize {
        self.segments
            .iter()
            .filter(|s| matches!(s, Segment::Sealed { .. }))
            .count()
    }

    /// Paths of every sealed segment, in index order.
    ///
    /// A checksum scan runs per file, so a verify pass needs the file list rather than the records:
    /// it re-reads each segment from disk and compares what is there against the headers written
    /// with it, which is a different question from "does the in-memory index agree with itself".
    pub fn sealed_paths(&self) -> Vec<&Path> {
        self.segments
            .iter()
            .filter_map(|s| match s {
                Segment::Sealed { path, .. } => Some(path.as_path()),
                Segment::Active { .. } => None,
            })
            .collect()
    }

    /// Payload bytes currently held in RAM by the active segment — the observable form of the
    /// memory bound the segment target sets.
    pub fn resident_bytes(&self) -> usize {
        self.segments
            .iter()
            .map(|s| match s {
                Segment::Active { live, .. } => live.values().map(|b| b.len()).sum(),
                Segment::Sealed { .. } => 0,
            })
            .sum()
    }

    fn segment(&self, index: u32) -> Option<&Segment> {
        // Index order is maintained on push, so this is a direct hit in practice; the guard covers
        // a caller passing an index we never issued.
        self.segments
            .get(index as usize)
            .filter(|s| s.index() == index)
            .or_else(|| self.segments.iter().find(|s| s.index() == index))
    }

    fn active(&self) -> anyhow::Result<&Segment> {
        match self.segments.last() {
            Some(s @ Segment::Active { .. }) => Ok(s),
            _ => bail!("no active segment"),
        }
    }

    fn next_index(&self) -> u32 {
        self.segments.last().map_or(0, |s| s.index() + 1)
    }
}

/// Walk a segment file end to end, checking every record against its own header.
///
/// A bad file header is an `Err` — it is a fault in the file as a whole, not in one record. A bad
/// record sets `corruption` and stops the walk, returning the records already read.
pub fn scan_segment_file(path: &Path) -> anyhow::Result<SegmentScan> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading segment {}", path.display()))?;
    let index = index_from_file_name(path);
    if bytes.len() < SEGMENT_FILE_HEADER_LEN {
        bail!(
            "{} is {} bytes, too short to hold a {SEGMENT_FILE_HEADER_LEN}-byte segment header",
            path.display(),
            bytes.len()
        );
    }
    if bytes[..8] != SEGMENT_MAGIC {
        bail!(
            "{} is not a burpsy segment file (bad magic)",
            path.display()
        );
    }
    if bytes[8] != SEGMENT_FORMAT_VERSION {
        bail!(
            "{} is segment format version {}, but this build understands version {}",
            path.display(),
            bytes[8],
            SEGMENT_FORMAT_VERSION
        );
    }

    let mut records = Vec::new();
    let mut corruption = None;
    let mut at = SEGMENT_FILE_HEADER_LEN;
    while at < bytes.len() {
        let header = match RecordHeader::decode(at, &bytes[at..]) {
            Ok(h) => h,
            Err(fault) => {
                corruption = Some(fault);
                break;
            }
        };
        let declared = header.len as usize;
        let payload_offset = at + RECORD_HEADER_LEN;
        let end = match payload_offset.checked_add(declared) {
            Some(end) if end <= bytes.len() => end,
            _ => {
                corruption = Some(CorruptRecord::LengthOverrunsSegment {
                    at,
                    declared,
                    segment_len: bytes.len(),
                });
                break;
            }
        };
        let recomputed = crc32fast::hash(&bytes[payload_offset..end]);
        if recomputed != header.crc32 {
            corruption = Some(CorruptRecord::ChecksumMismatch {
                at,
                id: header.msg_id,
                stored: header.crc32,
                recomputed,
            });
            break;
        }
        records.push((
            header,
            Location {
                segment: index,
                offset: payload_offset,
                len: declared,
            },
        ));
        at = end;
    }

    Ok(SegmentScan {
        index,
        records,
        corruption,
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A unique capture directory that removes itself. Cheaper than a `tempfile` dev-dependency,
    /// which this workspace does not otherwise have.
    pub(crate) struct TempCapture(PathBuf);

    impl TempCapture {
        pub(crate) fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("burpsy-capture-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            Self(dir)
        }
        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempCapture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::TempCapture;
    use super::*;

    fn log(target: usize) -> (TempCapture, SegmentLog) {
        let t = TempCapture::new();
        let l = SegmentLog::open(t.path(), target).expect("open");
        (t, l)
    }

    // ---- Task 1: header formats ----

    #[test]
    fn a_record_header_round_trips_every_field() {
        for (len, dir) in [
            (0u32, Direction::Request),
            (1, Direction::Response),
            (u32::MAX, Direction::Request),
            (4096, Direction::Response),
        ] {
            let h = RecordHeader {
                len,
                msg_id: MsgId(0xDEAD_BEEF_CAFE_F00D),
                direction: dir,
                crc32: 0x1234_5678,
            };
            let got = RecordHeader::decode(0, &h.encode()).expect("decode");
            assert_eq!(got, h, "header did not survive an encode/decode round trip");
        }
    }

    #[test]
    fn a_header_read_from_too_few_bytes_names_what_was_missing() {
        for have in 0..RECORD_HEADER_LEN {
            let err = RecordHeader::decode(64, &vec![0u8; have]).expect_err("must refuse");
            assert_eq!(
                err,
                CorruptRecord::ShortHeader {
                    at: 64,
                    need: RECORD_HEADER_LEN,
                    have
                }
            );
            assert_eq!(err.at(), 64);
        }
    }

    #[test]
    fn a_direction_byte_outside_the_encoded_set_is_corruption_not_a_default() {
        let mut raw = RecordHeader {
            len: 3,
            msg_id: MsgId(7),
            direction: Direction::Request,
            crc32: 0,
        }
        .encode();
        raw[12] = 2;
        let err = RecordHeader::decode(99, &raw).expect_err("must refuse");
        assert_eq!(err, CorruptRecord::UnknownDirection { at: 99, byte: 2 });
    }

    #[test]
    fn a_fresh_segment_file_starts_with_the_magic_and_version() {
        let (t, mut l) = log(4096);
        l.append(MsgId(0), Direction::Request, &Bytes::from_static(b"hi"))
            .expect("append");
        l.flush_active().expect("flush");
        let raw = std::fs::read(t.path().join(tmp_file_name(0))).expect("read");
        assert_eq!(&raw[..8], &SEGMENT_MAGIC);
        assert_eq!(raw[8], SEGMENT_FORMAT_VERSION);
        assert!(
            raw[9..SEGMENT_FILE_HEADER_LEN].iter().all(|b| *b == 0),
            "reserved bytes must be zero"
        );
    }

    #[test]
    fn a_directory_holding_a_foreign_segment_file_is_refused_by_name() {
        let t = TempCapture::new();
        std::fs::create_dir_all(t.path()).expect("mkdir");
        let bogus = t.path().join(segment_file_name(0));
        std::fs::write(&bogus, b"NOTBURPSY_and_then_some_padding").expect("write");
        let err = SegmentLog::open(t.path(), 4096).expect_err("must refuse");
        assert!(
            err.to_string().contains("segment-000000.log"),
            "refusal must name the file: {err}"
        );
        assert!(err.to_string().contains("bad magic"), "got: {err}");
    }

    #[test]
    fn a_directory_holding_a_future_format_version_is_refused_by_version() {
        let t = TempCapture::new();
        std::fs::create_dir_all(t.path()).expect("mkdir");
        let mut head = [0u8; SEGMENT_FILE_HEADER_LEN];
        head[..8].copy_from_slice(&SEGMENT_MAGIC);
        head[8] = SEGMENT_FORMAT_VERSION + 9;
        std::fs::write(t.path().join(segment_file_name(0)), head).expect("write");
        let err = SegmentLog::open(t.path(), 4096).expect_err("must refuse");
        assert!(
            err.to_string().contains("format version"),
            "refusal must name the version: {err}"
        );
    }

    #[test]
    fn a_zero_target_is_refused_rather_than_rotating_on_every_record() {
        let t = TempCapture::new();
        assert!(SegmentLog::open(t.path(), 0).is_err());
    }

    #[test]
    fn a_directory_holding_a_previous_capture_is_not_silently_overwritten() {
        let t = TempCapture::new();
        {
            let mut l = SegmentLog::open(t.path(), 64).expect("open");
            l.append(MsgId(0), Direction::Request, &Bytes::from(vec![b'x'; 200]))
                .expect("append");
        }
        let err = SegmentLog::open(t.path(), 64).expect_err("must refuse");
        assert!(
            err.to_string().contains("previous capture"),
            "refusal must explain why: {err}"
        );
    }

    // ---- Task 2: append, resolve, rotation ----

    #[test]
    fn an_appended_payload_resolves_back_byte_identically() {
        let (_t, mut l) = log(4096);
        let payload = Bytes::from_static(b"GET / HTTP/1.1\r\nHost: x.test\r\n\r\n");
        let loc = l
            .append(MsgId(0), Direction::Request, &payload)
            .expect("append");
        assert_eq!(loc.len, payload.len());
        assert_eq!(loc.offset, SEGMENT_FILE_HEADER_LEN + RECORD_HEADER_LEN);
        assert_eq!(l.resolve(loc).expect("resolve"), payload);
    }

    #[test]
    fn resolving_an_active_record_is_zero_copy() {
        let (_t, mut l) = log(4096);
        let payload = Bytes::from(vec![b'a'; 512]);
        let loc = l
            .append(MsgId(0), Direction::Response, &payload)
            .expect("append");
        let got = l.resolve(loc).expect("resolve");
        assert_eq!(
            got.as_ptr(),
            payload.as_ptr(),
            "active resolution must share the caller's allocation, not copy it"
        );
    }

    #[test]
    fn a_zero_length_payload_is_a_real_record_not_a_skipped_one() {
        let (_t, mut l) = log(4096);
        let loc = l
            .append(MsgId(0), Direction::Request, &Bytes::new())
            .expect("append");
        assert_eq!(loc.len, 0);
        let got = l.resolve(loc).expect("a zero-length record still resolves");
        assert!(got.is_empty());
    }

    #[test]
    fn a_location_naming_an_unknown_segment_resolves_to_none() {
        let (_t, mut l) = log(4096);
        l.append(MsgId(0), Direction::Request, &Bytes::from_static(b"x"))
            .expect("append");
        assert!(
            l.resolve(Location {
                segment: 99,
                offset: SEGMENT_FILE_HEADER_LEN + RECORD_HEADER_LEN,
                len: 1
            })
            .is_none()
        );
    }

    #[test]
    fn a_span_that_overruns_its_segment_resolves_to_none_rather_than_reading_past_the_end() {
        let (_t, mut l) = log(4096);
        let loc = l
            .append(MsgId(0), Direction::Request, &Bytes::from_static(b"short"))
            .expect("append");
        assert!(
            l.resolve(Location {
                len: 1 << 20,
                ..loc
            })
            .is_none()
        );
        assert!(
            l.resolve(Location {
                offset: usize::MAX - 1,
                len: 8,
                ..loc
            })
            .is_none(),
            "offset + len must not be allowed to wrap"
        );
    }

    #[test]
    fn passing_the_target_rotates_and_every_earlier_location_still_resolves() {
        // Target admits a couple of ~100-byte records per segment, so this rotates several times.
        let (_t, mut l) = log(SEGMENT_FILE_HEADER_LEN + 3 * (RECORD_HEADER_LEN + 100));
        let mut issued = Vec::new();
        for i in 0..40u64 {
            let payload = Bytes::from(format!("{i:0>100}"));
            let loc = l
                .append(MsgId(i), Direction::Request, &payload)
                .expect("append");
            issued.push((loc, payload));
        }
        assert!(
            l.sealed_count() > 1,
            "expected rotation to have sealed segments"
        );
        assert!(l.segment_count() > 1);
        for (loc, expected) in &issued {
            assert_eq!(
                &l.resolve(*loc).expect("every issued location resolves"),
                expected,
                "rotation must not disturb an earlier record"
            );
        }
    }

    #[test]
    fn an_oversized_message_gets_its_own_segment_rather_than_being_refused() {
        let target = 256;
        let (_t, mut l) = log(target);
        let small = Bytes::from_static(b"first");
        let small_loc = l
            .append(MsgId(0), Direction::Request, &small)
            .expect("append");
        let huge = Bytes::from(vec![b'z'; target * 5]);
        let huge_loc = l
            .append(MsgId(1), Direction::Response, &huge)
            .expect("append");

        assert_ne!(
            huge_loc.segment, small_loc.segment,
            "an oversized record must not share a segment"
        );
        assert_eq!(
            huge_loc.offset,
            SEGMENT_FILE_HEADER_LEN + RECORD_HEADER_LEN,
            "an oversized record is the only record in its segment"
        );
        assert_eq!(
            l.resolve(huge_loc).expect("resolve"),
            huge,
            "an oversized payload must survive whole"
        );
        assert_eq!(l.resolve(small_loc).expect("resolve"), small);
    }

    #[test]
    fn resident_bytes_tracks_the_active_segment_and_drops_after_a_rotation() {
        let (_t, mut l) = log(SEGMENT_FILE_HEADER_LEN + RECORD_HEADER_LEN + 100);
        assert_eq!(l.resident_bytes(), 0);
        l.append(MsgId(0), Direction::Request, &Bytes::from(vec![b'a'; 100]))
            .expect("append");
        assert_eq!(l.resident_bytes(), 100);
        // The next record cannot fit, so the segment holding the first one seals and its payload
        // stops being resident.
        l.append(MsgId(1), Direction::Request, &Bytes::from(vec![b'b'; 100]))
            .expect("append");
        assert_eq!(
            l.resident_bytes(),
            100,
            "only the new active segment's payload stays resident"
        );
        assert_eq!(l.sealed_count(), 1);
    }

    // ---- Task 3: seal lifecycle ----

    #[test]
    fn sealing_renames_the_tmp_file_to_its_final_name() {
        let (t, mut l) = log(4096);
        l.append(MsgId(0), Direction::Request, &Bytes::from_static(b"body"))
            .expect("append");
        l.seal_active().expect("seal");
        assert!(
            !t.path().join(tmp_file_name(0)).exists(),
            ".tmp must be gone"
        );
        assert!(t.path().join(segment_file_name(0)).exists());
    }

    #[test]
    fn a_record_resolves_to_the_same_bytes_after_its_segment_seals() {
        let (_t, mut l) = log(4096);
        let payload = Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\nhello");
        let loc = l
            .append(MsgId(0), Direction::Response, &payload)
            .expect("append");
        let before = l.resolve(loc).expect("resolve while active");
        l.seal_active().expect("seal");
        let after = l.resolve(loc).expect("resolve once sealed");
        assert_eq!(before, after);
        assert_eq!(after, payload);
    }

    #[test]
    fn sealing_stops_the_payload_being_resident() {
        let (_t, mut l) = log(1 << 20);
        l.append(MsgId(0), Direction::Request, &Bytes::from(vec![b'a'; 400]))
            .expect("append");
        assert_eq!(l.resident_bytes(), 400);
        l.seal_active().expect("seal");
        assert_eq!(l.resident_bytes(), 0);
    }

    #[test]
    fn scanning_a_clean_segment_returns_every_record_in_append_order() {
        let (t, mut l) = log(1 << 20);
        let mut expected = Vec::new();
        for i in 0..5u64 {
            let payload = Bytes::from(format!("record-{i}"));
            l.append(MsgId(i), Direction::Request, &payload)
                .expect("append");
            expected.push((MsgId(i), payload));
        }
        l.seal_active().expect("seal");
        let scan = scan_segment_file(&t.path().join(segment_file_name(0))).expect("scan");
        assert!(
            scan.corruption.is_none(),
            "clean file must report no corruption"
        );
        assert_eq!(scan.index, 0);
        assert_eq!(scan.records.len(), 5);
        for ((header, loc), (id, payload)) in scan.records.iter().zip(&expected) {
            assert_eq!(header.msg_id, *id);
            assert_eq!(loc.len, payload.len());
            assert_eq!(header.crc32, crc32fast::hash(payload));
        }
    }

    #[test]
    fn a_flipped_payload_byte_is_reported_as_a_checksum_mismatch_naming_the_id() {
        let (t, mut l) = log(1 << 20);
        l.append(
            MsgId(0),
            Direction::Request,
            &Bytes::from_static(b"first-record"),
        )
        .expect("append");
        l.append(
            MsgId(41),
            Direction::Response,
            &Bytes::from_static(b"second-record"),
        )
        .expect("append");
        l.seal_active().expect("seal");

        let path = t.path().join(segment_file_name(0));
        // Flip a byte inside the *second* record's payload, so the first must still be readable.
        let second_payload =
            SEGMENT_FILE_HEADER_LEN + RECORD_HEADER_LEN + b"first-record".len() + RECORD_HEADER_LEN;
        let mut f = OpenOptions::new().write(true).open(&path).expect("open rw");
        f.seek(SeekFrom::Start(second_payload as u64))
            .expect("seek");
        f.write_all(b"X").expect("flip");
        drop(f);

        let scan = scan_segment_file(&path).expect("scan");
        match scan.corruption.expect("must report corruption") {
            CorruptRecord::ChecksumMismatch {
                id,
                stored,
                recomputed,
                ..
            } => {
                assert_eq!(id, MsgId(41), "the verdict must name the failing record");
                assert_ne!(stored, recomputed);
            }
            other => panic!("expected a checksum mismatch, got {other}"),
        }
        assert_eq!(
            scan.records.len(),
            1,
            "records read before the fault are still returned"
        );
    }

    #[test]
    fn a_truncated_final_record_is_reported_not_panicked_on() {
        let (t, mut l) = log(1 << 20);
        l.append(MsgId(0), Direction::Request, &Bytes::from(vec![b'q'; 300]))
            .expect("append");
        l.seal_active().expect("seal");
        let path = t.path().join(segment_file_name(0));
        let full = std::fs::metadata(&path).expect("stat").len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open rw")
            .set_len(full - 100)
            .expect("truncate");

        let scan = scan_segment_file(&path).expect("scan");
        match scan.corruption.expect("must report corruption") {
            CorruptRecord::LengthOverrunsSegment { declared, .. } => assert_eq!(declared, 300),
            other => panic!("expected a length overrun, got {other}"),
        }
    }

    #[test]
    fn a_segment_that_fails_its_own_seal_scan_is_never_mapped() {
        // Corrupt the .tmp file behind the writer's back, so the scan that seal runs after the
        // rename is the thing that catches it.
        let (t, mut l) = log(1 << 20);
        l.append(
            MsgId(5),
            Direction::Request,
            &Bytes::from_static(b"payload-to-corrupt"),
        )
        .expect("append");
        l.flush_active().expect("flush");
        let tmp = t.path().join(tmp_file_name(0));
        let mut f = OpenOptions::new().write(true).open(&tmp).expect("open rw");
        f.seek(SeekFrom::Start(
            (SEGMENT_FILE_HEADER_LEN + RECORD_HEADER_LEN) as u64,
        ))
        .expect("seek");
        f.write_all(b"!").expect("flip");
        drop(f);

        let err = l
            .seal_active()
            .expect_err("seal must refuse a corrupt segment");
        let msg = err.to_string();
        assert!(msg.contains("failed its seal scan"), "got: {msg}");
        assert!(
            msg.contains("byte"),
            "the error must name the offset: {msg}"
        );
        assert_eq!(
            l.sealed_count(),
            0,
            "a failed seal must not produce a sealed segment"
        );
    }

    #[test]
    fn header_at_returns_the_on_disk_header_for_a_sealed_record() {
        let (_t, mut l) = log(1 << 20);
        let payload = Bytes::from_static(b"look-at-my-header");
        let loc = l
            .append(MsgId(77), Direction::Response, &payload)
            .expect("append");
        l.seal_active().expect("seal");
        let header = l.header_at(loc).expect("header");
        assert_eq!(header.msg_id, MsgId(77));
        assert_eq!(header.len as usize, payload.len());
        assert_eq!(header.direction, Direction::Response);
        assert_eq!(header.crc32, crc32fast::hash(&payload));
    }

    #[test]
    fn header_at_reads_an_active_record_once_flushed() {
        let (_t, mut l) = log(1 << 20);
        let payload = Bytes::from_static(b"still-active");
        let loc = l
            .append(MsgId(3), Direction::Request, &payload)
            .expect("append");
        l.flush_active().expect("flush");
        let header = l.header_at(loc).expect("header");
        assert_eq!(header.msg_id, MsgId(3));
        assert_eq!(header.crc32, crc32fast::hash(&payload));
    }

    #[test]
    fn header_at_refuses_a_location_that_cannot_have_a_header_before_it() {
        let (_t, mut l) = log(1 << 20);
        l.append(MsgId(0), Direction::Request, &Bytes::from_static(b"x"))
            .expect("append");
        let err = l
            .header_at(Location {
                segment: 0,
                offset: 0,
                len: 1,
            })
            .expect_err("offset 0 has no room for a header");
        assert!(matches!(err, CorruptRecord::ShortHeader { .. }));
    }

    #[test]
    fn sealed_paths_lists_every_sealed_segment_and_never_the_active_one() {
        let (t, mut l) = log(SEGMENT_FILE_HEADER_LEN + RECORD_HEADER_LEN + 100);
        for i in 0..3u64 {
            l.append(MsgId(i), Direction::Request, &Bytes::from(vec![b'a'; 100]))
                .expect("append");
        }
        let sealed = l.sealed_paths();
        assert_eq!(sealed.len(), l.sealed_count());
        assert_eq!(
            sealed.len(),
            l.segment_count() - 1,
            "the active segment is not listed"
        );
        for (i, p) in sealed.iter().enumerate() {
            assert_eq!(*p, t.path().join(segment_file_name(i as u32)));
            assert!(
                p.exists(),
                "a sealed path must name a file that is really there"
            );
        }
    }

    #[test]
    fn scanning_a_file_that_is_not_a_segment_is_an_error_not_a_corruption_report() {
        let t = TempCapture::new();
        std::fs::create_dir_all(t.path()).expect("mkdir");
        let path = t.path().join(segment_file_name(0));
        std::fs::write(&path, b"this is not a segment file at all").expect("write");
        assert!(
            scan_segment_file(&path).is_err(),
            "a bad file header is a whole-file fault, not a per-record one"
        );
    }
}
