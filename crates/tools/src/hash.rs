//! Hash — the Decoder's third action, and the only one with no inverse.
//!
//! Burp's Decoder offers "Hash..." beside decode and encode, and it is deliberately *not* modelled
//! here as another [`crate::decoder::Layer`]. A `Layer` is a claim about framing: the bytes
//! underneath are still there, and `decode`/`encode` move between the two views. A digest destroys
//! its input. Folding it into that enum would put a permanent
//! [`DecodeError::NotReversible`](crate::decoder::DecodeError::NotReversible) arm on every `encode`
//! call site for an operation that is not reversible *in principle* — which is not what that
//! variant means. It means [`Layer::Jwt`](crate::decoder::Layer::Jwt): re-encoding needs a signing
//! key we do not have, not a break in a hash function.
//!
//! MD5 and SHA-1 are offered despite being broken for anything needing collision resistance,
//! because an operator hashing bytes next to a proxy is not *choosing* a primitive — they are
//! reproducing one the target already chose. A tool that refused to compute MD5 would only move
//! that work to another window, with the bytes copied by hand.
//!
//! The digest crates earn their place for the reason `flate2` does: these are specified bit
//! twiddles where a subtle error yields a plausible-looking wrong answer rather than a failure, and
//! a wrong digest is worse than no digest — it reads as proof that two things differ.

use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// One one-way digest. Burp's four, which are also the four a target is likely to have used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// Broken for collision resistance since 2004. Kept because targets still use it.
    Md5,
    /// Broken for collision resistance since 2017 (SHAttered). Kept for the same reason.
    Sha1,
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            HashAlgorithm::Md5 => "md5",
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
        }
    }

    /// Parse the name used on the wire. Returns `None` rather than guessing.
    ///
    /// Note what is absent: `"sha2"` and `"sha"`. Both name a *family*, and picking a member for
    /// the caller would hand back a digest of the wrong length under a name they chose — the one
    /// mistake in this module that a caller cannot see in the output.
    pub fn parse(s: &str) -> Option<HashAlgorithm> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "md5" | "md-5" => HashAlgorithm::Md5,
            "sha1" | "sha-1" => HashAlgorithm::Sha1,
            "sha256" | "sha-256" => HashAlgorithm::Sha256,
            "sha512" | "sha-512" => HashAlgorithm::Sha512,
            _ => return None,
        })
    }

    /// Every algorithm, in the order the UI should list them — weakest first, matching Burp's menu.
    pub const ALL: [HashAlgorithm; 4] = [
        HashAlgorithm::Md5,
        HashAlgorithm::Sha1,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha512,
    ];

    /// Length of the digest in bytes. Fixed per algorithm, so a caller can size a buffer or check
    /// a pasted digest's plausibility without hashing anything.
    pub fn digest_len(self) -> usize {
        match self {
            HashAlgorithm::Md5 => 16,
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

/// Digest the whole input. Raw bytes, not hex: the caller decides on a presentation, and
/// [`crate::decoder::hex_encode`] is right there for the usual one.
///
/// Infallible by construction — there is no such thing as input a hash function rejects, which is
/// exactly why this returns `Vec<u8>` rather than a `Result` the caller would have to pretend to
/// handle.
pub fn hash(algorithm: HashAlgorithm, input: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Md5 => Md5::digest(input).to_vec(),
        HashAlgorithm::Sha1 => Sha1::digest(input).to_vec(),
        HashAlgorithm::Sha256 => Sha256::digest(input).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(input).to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::hex_encode;

    fn hex(algorithm: HashAlgorithm, input: &[u8]) -> String {
        String::from_utf8(hex_encode(&hash(algorithm, input))).expect("hex is ASCII")
    }

    /// The published empty-input digests. These are the vectors worth hardcoding: every one of the
    /// four is quotable from its own specification, so a padding bug — the classic way to get a
    /// hash *almost* right — cannot hide behind a self-consistent round trip.
    #[test]
    fn the_empty_input_matches_the_published_digests() {
        assert_eq!(
            hex(HashAlgorithm::Md5, b""),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            hex(HashAlgorithm::Sha1, b""),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex(HashAlgorithm::Sha256, b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(HashAlgorithm::Sha512, b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    /// `"abc"` — the one-block NIST vector, which exercises the length encoding on a non-empty
    /// message rather than only the degenerate case above.
    #[test]
    fn abc_matches_the_nist_vectors() {
        assert_eq!(
            hex(HashAlgorithm::Md5, b"abc"),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex(HashAlgorithm::Sha1, b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(HashAlgorithm::Sha256, b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(HashAlgorithm::Sha512, b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    /// Past one block, where an incorrect buffer-carry stops being invisible.
    #[test]
    fn a_multi_block_input_hashes_correctly() {
        let long = b"the quick brown fox jumps over the lazy dog".repeat(40);
        assert_eq!(long.len(), 1720, "26 SHA-256 blocks and a partial one");
        assert_eq!(
            hex(HashAlgorithm::Sha256, &long),
            "3bc7fc2d8aaed889a294c74a65ce272d1677ffde4b6dadd0fc6fb91802c8cf96"
        );
    }

    #[test]
    fn every_digest_is_the_advertised_length_and_binary_safe() {
        // Raw bytes, not hex, and not UTF-8-constrained: a digest of a PNG is a digest, and
        // returning `String` here would have forced a lossy conversion on half of all outputs.
        for a in HashAlgorithm::ALL {
            assert_eq!(hash(a, b"").len(), a.digest_len(), "{}", a.as_str());
            assert_eq!(hash(a, &[0u8, 0xff, 0x80]).len(), a.digest_len());
        }
    }

    #[test]
    fn names_round_trip_and_an_unknown_one_is_refused_not_guessed() {
        for a in HashAlgorithm::ALL {
            assert_eq!(HashAlgorithm::parse(a.as_str()), Some(a));
        }
        assert_eq!(
            HashAlgorithm::parse(" SHA-256 "),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(HashAlgorithm::parse("MD-5"), Some(HashAlgorithm::Md5));
        // A family name is not an algorithm: guessing a member would silently return the wrong
        // digest length under the name the caller asked for.
        assert_eq!(HashAlgorithm::parse("sha2"), None);
        assert_eq!(HashAlgorithm::parse("sha"), None);
        assert_eq!(HashAlgorithm::parse("sha384"), None);
        assert_eq!(HashAlgorithm::parse("crc32"), None);
        assert_eq!(HashAlgorithm::parse(""), None);
    }

    /// Distinct algorithms must not alias. Trivially true, and it is the assertion that would fail
    /// if the `match` in [`hash`] ever gained a copy-pasted arm.
    #[test]
    fn each_algorithm_produces_a_distinct_digest() {
        let all: Vec<String> = HashAlgorithm::ALL
            .iter()
            .map(|&a| hex(a, b"burpsy"))
            .collect();
        for (i, x) in all.iter().enumerate() {
            for y in &all[i + 1..] {
                assert_ne!(x, y);
            }
        }
    }
}
