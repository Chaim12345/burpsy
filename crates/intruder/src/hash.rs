//! MD5 and SHA-256, for the payload-processing hash step.
//!
//! # Why this is here and not in `burpsy_tools::decoder`
//!
//! It should be there. The Decoder is where every other codec in this workspace lives, and an
//! operator who wants "hash this" in the Decoder and "hash this payload" in the Intruder should be
//! getting one implementation. This copy exists because the Decoder-hashing work is landing in
//! parallel and two agents editing `decoder.rs` produce a merge conflict rather than a feature.
//!
//! **This is duplication, and it is meant to be removed.** When `burpsy_tools::decoder` grows
//! `Hash`/`hash(alg, bytes)`, delete this module and point [`crate::process`] at it: the crate
//! already depends on `burpsy-tools`, so nothing else has to change. The public surface here is
//! deliberately two functions and an enum, so that swap is a one-line edit per call site.
//!
//! # Why hand-written rather than `sha2` + `md-5`
//!
//! This crate's manifest is narrowed on purpose (no `net` in tokio, and it says so in a comment), and
//! a module that is scheduled for deletion is a poor reason to add three transitive dependencies to
//! it. Both algorithms are short, fixed, and have canonical published vectors — which the tests at
//! the bottom check, so "hand-written" here means "checked against RFC 1321 and FIPS 180-4", not
//! "trusted".
//!
//! Neither is used for a security decision. A payload processing rule hashes the operator's own
//! payload so it can be sent somewhere that expects a digest; MD5 is offered *because* targets still
//! use it, not as a recommendation.

use serde::{Deserialize, Serialize};

/// The digests a payload processing rule can apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlg {
    Md5,
    Sha256,
}

impl HashAlg {
    pub fn as_str(self) -> &'static str {
        match self {
            HashAlg::Md5 => "md5",
            HashAlg::Sha256 => "sha256",
        }
    }

    /// Parse the wire name. `None` rather than a default: an unrecognised algorithm must be an error
    /// at the edge, not a silent fallback that hashes with something the operator did not ask for.
    pub fn parse(s: &str) -> Option<HashAlg> {
        match s.trim().to_ascii_lowercase().as_str() {
            "md5" | "md-5" => Some(HashAlg::Md5),
            "sha256" | "sha-256" | "sha2" => Some(HashAlg::Sha256),
            _ => None,
        }
    }

    /// The digest of `input`, as raw bytes.
    pub fn digest(self, input: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Md5 => md5(input).to_vec(),
            HashAlg::Sha256 => sha256(input).to_vec(),
        }
    }

    /// The digest of `input`, as lowercase hex.
    ///
    /// Hex rather than raw bytes because a payload gets spliced into a request: raw digest bytes in a
    /// URL or a form field are almost always wrong, and an operator who wants base64 can chain an
    /// encode rule after this one.
    pub fn hex(self, input: &[u8]) -> String {
        let d = self.digest(input);
        let mut s = String::with_capacity(d.len() * 2);
        for b in d {
            s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
        }
        s
    }
}

/// The length-and-padding tail both algorithms share: a `0x80` byte, zeroes, then the message length
/// in bits as a 64-bit integer. They disagree only on the endianness of that integer.
fn padded_len(len: usize) -> usize {
    // The block containing 0x80 plus 8 length bytes, rounded up to 64.
    (len + 9).div_ceil(64) * 64
}

// ---- MD5 (RFC 1321) ------------------------------------------------------------------------

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// `floor(abs(sin(i + 1)) * 2^32)`, as RFC 1321 specifies. Written out rather than computed so the
/// values do not depend on the platform's `sin`.
const MD5_K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// MD5 of `input`.
pub fn md5(input: &[u8]) -> [u8; 16] {
    let mut msg = Vec::with_capacity(padded_len(input.len()));
    msg.extend_from_slice(input);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    // Little-endian bit length: the one place MD5 and SHA-256 disagree about padding.
    msg.extend_from_slice(&(input.len() as u64).wrapping_mul(8).to_le_bytes());

    let mut h: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    for block in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in block.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let [mut a, mut b, mut c, mut d] = h;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                f.wrapping_add(a)
                    .wrapping_add(MD5_K[i])
                    .wrapping_add(m[g])
                    .rotate_left(MD5_S[i]),
            );
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for (i, w) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

// ---- SHA-256 (FIPS 180-4) ------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// SHA-256 of `input`.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(padded_len(input.len()));
    msg.extend_from_slice(input);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    // Big-endian bit length.
    msg.extend_from_slice(&(input.len() as u64).wrapping_mul(8).to_be_bytes());

    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, b) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(v);
        }
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1321 appendix A.5's own test suite. Hand-written code earns trust from published vectors
    /// or not at all.
    #[test]
    fn md5_matches_the_rfc_1321_test_suite() {
        for (input, want) in [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ] {
            assert_eq!(
                HashAlg::Md5.hex(input.as_bytes()),
                want,
                "md5({input:?}) is wrong"
            );
        }
    }

    /// FIPS 180-4's published vectors, plus the two block-boundary cases that catch a padding bug:
    /// 55 bytes fits in one block with its length, 56 does not and forces a second.
    #[test]
    fn sha256_matches_the_fips_180_4_vectors() {
        for (input, want) in [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            assert_eq!(
                HashAlg::Sha256.hex(input.as_bytes()),
                want,
                "sha256({input:?}) is wrong"
            );
        }
        // 55 and 56 bytes: the boundary where the length no longer fits in the final block.
        assert_eq!(
            HashAlg::Sha256.hex(&b"a".repeat(55)),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );
        assert_eq!(
            HashAlg::Sha256.hex(&b"a".repeat(56)),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
    }

    #[test]
    fn an_unknown_algorithm_is_refused_not_defaulted() {
        assert_eq!(HashAlg::parse("SHA-256"), Some(HashAlg::Sha256));
        assert_eq!(HashAlg::parse("md5"), Some(HashAlg::Md5));
        assert_eq!(HashAlg::parse("sha1"), None);
        assert_eq!(HashAlg::parse(""), None);
    }
}
