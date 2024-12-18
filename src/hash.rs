#![allow(unused)]
#![cfg(feature = "hash")]

// this file has a lot of one letter names and is incredibly vague, check the SHA standard for more information

fn ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ (!e & g)
}

fn maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

fn pad(message: &[u8]) -> Vec<u8> {
    let length = message.len();
    let bit_length = (length * 8) as u64;
    let mut padded = message.to_vec();

    padded.push(0x80);

    while ((padded.len() - 1) * 8 + 72) % 512 != 0 {
        padded.push(0x00);
    }

    padded.append(&mut bit_length.to_be_bytes().to_vec());
    padded
}

fn join_bytes_to_u32(bytes: &[u8]) -> u32 {
    let part_1 = (bytes[0] as u32) << 24;
    let part_2 = (bytes[1] as u32) << 16;
    let part_3 = (bytes[2] as u32) << 8;
    let part_4 = (bytes[3] as u32);

    (part_1 | part_2) | (part_3 | part_4)
}

// fn modular_add(small: &[u64]) -> u32 {
//     let mut sum: u64 = 0;
//     for num in small {
//         sum += *num;
//         sum %= 2u64.pow(32);
//     }
//     sum as u32
// }
fn modular_add(small: &[u32]) -> u32 {
    small.iter().fold(0, |acc, n| acc.overflowing_add(*n).0)
}

fn rotate_right(x: u32, shift: u32) -> u64 {
    (x as u64 >> shift as u64) | ((x as u64) << (32 - shift as u64))
}

fn rotate_left(x: u32, shift: u32) -> u64 {
    ((x as u64) << shift as u64) | ((x as u64) >> (32 - shift as u64))
}

/// Computes a hash in SHA256
/// 
/// Call the `as_hex()` method or `of()` method for use.
pub mod sha256 {
    use std::iter::zip;
    use super::*;
    
    const K: [u32; 64] =
       [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
        
    const H: [u32; 8] = 
       [0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19];

    fn sigma0(a: u32) -> u64 {
        rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)
    }

    fn sigma1(e: u32) -> u64 {
        rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)
    }

    fn o0(x: u32) -> u64 {
        rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3) as u64
    }

    fn o1(x: u32) -> u64 {
        rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10) as u64
    }

    /// Returns a SHA256 digest of the message.
    /// 
    /// Differs from the `as_hex()` method, as this function returns a `Vec<u8>`, instead of a string of hex bytes.
    /// Use `as_hex()` in most cases, unless something requires for a `Vec<u8>` to be used instead.
    /// 
    /// # Example
    /// ```ignore
    /// let digest = sha256::of(b"hi");
    /// assert_eq!(digest, vec![/* the hash contents */]);
    /// ```
    pub fn of(message: &[u8]) -> Vec<u8> {
        let padded = pad(message);
        let mut h = H;

        for chunk in padded.chunks(64) {
            let w = compute_w(chunk);
            
            let v = h;
            let v = cycle(v, w, 0);
            for i in 0..8 {
                h[i] = modular_add(&[v[i], h[i]]);
            }
        };

        h.iter()
            .flat_map(|n| n.to_be_bytes())
            .collect()
    }

    fn cycle(mut v: [u32; 8], w: [u32; 64], i: usize) -> [u32; 8] {
        if i == 64 { return v }
        let ch = ch(v[4], v[5], v[6]);
        let maj = maj(v[0], v[1], v[2]);
        let sigma0 = sigma0(v[0]) as u32;
        let sigma1 = sigma1(v[4]) as u32;

        let t1 = modular_add(&[v[7], sigma1, ch, K[i], w[i]]);
        let t2 = modular_add(&[sigma0, maj]);

        v[7] = v[6];
        v[6] = v[5];
        v[5] = v[4];
        v[4] = modular_add(&[v[3], t1]);
        v[3] = v[2];
        v[2] = v[1];
        v[1] = v[0];
        v[0] = modular_add(&[t1, t2]);

        cycle(v, w, i + 1)
    }

    fn compute_w(message: &[u8]) -> [u32; 64] {
        let mut w = [0u32; 64];
        for (i, chunk) in zip(0..16, message.chunks(4)) {
            w[i] = join_bytes_to_u32(chunk);
        }

        for i in 16..64 {
            let o0 = o0(w[i-15]) as u32;
            let o1 = o1(w[i-2]) as u32;
            w[i] = modular_add(&[o1, w[i-7], o0, w[i-16]]);
        }

        w
    }
    
    /// Returns a SHA256 digest of the message, each byte formatted as hexadecimal
    /// 
    /// This function should be used for generating hashes, because this is the most common format for them.
    /// 
    /// # Example
    /// ```ignore
    /// let digest = sha256::as_hex(b"hi");
    /// assert_eq!(digest, "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4");
    /// ```
    pub fn as_hex(message: &[u8]) -> String {
        of(message).iter()
            .map(|byte| format!("{byte:02x}"))
            .fold(String::new(), |acc, byte| acc + &byte)
    }
}

/// Computes a hash in SHA1
/// 
/// Call the `as_hex()` method or `of()` method for use.
pub mod sha1 {
    use super::*;
    use std::iter::zip;
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    use std::{iter::zip, vec, arch::x86_64::__m128i, ptr};

    const K: [u32; 4] = 
       [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

    const H: [u32; 5] =
       [0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0];

    fn parity(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    fn f(x: u32, y: u32, z: u32, i: usize) -> u32 {
        match i {
        0..=19 => ch(x, y, z),
        20..=39 => parity(x, y, z),
        40..=59 => maj(x, y, z),
        60..=79 => parity(x, y, z),
        _ => unreachable!(),
        }
    }

    /// Returns a SHA1 digest of the message.
    /// 
    /// Differs from the `as_hex()` method, as this function returns a `Vec<u8>`, instead of a string of hex bytes.
    /// Use `as_hex()` in most cases, unless something requires for a `Vec<u8>` to be used instead.
    /// 
    /// # Example
    /// ```ignore
    /// let digest = sha1::of(b"hi");
    /// assert_eq!(digest, vec![/* the hash contents */]);
    /// ```
    #[cfg(not(target_feature = "sse2"))]
    pub fn of(message: &[u8]) -> Vec<u8> {
        let padded = pad(message);
        let mut h = H;

        for chunk in padded.chunks(64) {
            let w = compute_w(chunk);
            
            let v = h;
            let v = cycle(v, w, 0);

            for i in 0..5 {
                h[i] = modular_add(&[v[i], h[i]]);
            }
        };

        h.iter()
            .flat_map(|n| n.to_be_bytes())
            .collect()
    }

    // #[cfg(target_feature = "neon")]
    // pub fn of(message: &[u8]) -> Vec<u8> {

    // }
    
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    pub fn of(message: &[u8]) -> Vec<u8> {
        unsafe { accelerated_sha(message) }
    }

    #[inline(always)]
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    unsafe fn accelerated_sha(message: &[u8]) -> Vec<u8> {
        use std::arch::x86_64::{
            _mm_add_epi32,
            _mm_setzero_si128,
            _mm_set_epi32,
            _mm_sha1nexte_epu32,
            _mm_extract_epi32,
            _mm_loadu_si128,
            _mm_storeu_si128,
            _mm_shuffle_epi32,
        };
        use std::mem::{ transmute, size_of };

        let padded = pad(message);
        let mut abcd = _mm_loadu_si128(H.as_ptr().cast());
        let mut e = _mm_set_epi32(transmute(H[4]), 0, 0, 0);
            
        for chunk in padded.chunks(64) {
            let (new_abcd, new_e) = accelerated_cycle(abcd, e, chunk.as_ptr().cast());
            
            e = _mm_sha1nexte_epu32(new_e, e);
            abcd = _mm_add_epi32(abcd, new_abcd);
        }

        let mut slice = [0_i32; 5];
        _mm_storeu_si128(slice.as_mut_ptr().cast(), abcd);
        slice[4] = _mm_extract_epi32::<3>(e);

        slice.iter()
            .flat_map(|n| n.to_be_bytes())
            .collect()
    }
    
    #[inline(always)]
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    unsafe fn accelerated_cycle(mut abcd: __m128i, mut e: __m128i, message: *const u32) -> (__m128i, __m128i) {
        use std::arch::x86_64::{
            _mm_sha1msg1_epu32,
            _mm_sha1msg2_epu32,
            _mm_sha1nexte_epu32,
            _mm_sha1rnds4_epu32,
            _mm_setzero_si128,
            _mm_extract_epi32,
            _mm_shuffle_epi8,
            _mm_shuffle_epi32,
            _mm_loadu_si128,
            _mm_set_epi32,
            _mm_set_epi64x,
            _mm_add_epi32,
            _mm_xor_si128,
        };
        use std::mem::transmute;

        let abcd = _mm_shuffle_epi32(abcd, 0x1b);
        let mask = _mm_set_epi64x(0x0001020304050607, 0x08090a0b0c0d0e0f);

        let abcd_save = abcd; // movdqa abcd_SAVE, abcd
        let e_save = e; // movdqa E_SAVE, E

        // Rounds 0-3
        let msg0 = _mm_loadu_si128(message as *const __m128i);
        let msg0 = _mm_shuffle_epi8(msg0, mask);
        let e0 = _mm_add_epi32(e, msg0); 
        let e1 = abcd; 
        let abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);

        // Rounds 4-7
        let msg1 = _mm_loadu_si128(message.offset(4).cast());
        let msg1 = _mm_shuffle_epi8(msg1, mask);
        let e0 = abcd; 
        let e1 = _mm_sha1nexte_epu32(e1, msg1);
        let abcd = _mm_sha1rnds4_epu32::<0>(abcd, e1);
        let msg0 = _mm_sha1msg1_epu32(msg0, msg1);

        // Rounds 8-11
        let msg2 = _mm_loadu_si128(message.offset(8).cast());
        let msg2 = _mm_shuffle_epi8(msg2, mask);
        let e0 = _mm_sha1nexte_epu32(e0, msg2);
        let e1 = abcd;
        let abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
        let msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        let msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 12-15
        let msg3 = _mm_loadu_si128(message.offset(12).cast());
        let msg3 = _mm_shuffle_epi8(msg3, mask);
        let e1 = _mm_sha1nexte_epu32(e1, msg3);
        let e0 = abcd;
        let msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        let abcd = _mm_sha1rnds4_epu32::<0>(abcd, e1);
        let msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        let msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 16-19
        let e0 = _mm_sha1nexte_epu32(e0, msg0);
        let e1 = abcd;
        let msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        let abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);
        let msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        let msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 20-23
        let e1 = _mm_sha1nexte_epu32(e1, msg1);
        let e0 = abcd;
        let msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        let abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
        let msg0 = _mm_sha1msg1_epu32(msg0, msg1);
        let msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 24-27
        let e0 = _mm_sha1nexte_epu32(e0, msg2);
        let e1 = abcd;
        let msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        let abcd = _mm_sha1rnds4_epu32::<1>(abcd, e0);
        let msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        let msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 28-31
        let e1 = _mm_sha1nexte_epu32(e1, msg3);
        let e0 = abcd;
        let msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        let abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
        let msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        let msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 32-35
        let e0 = _mm_sha1nexte_epu32(e0, msg0);
        let e1 = abcd;
        let msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        let abcd = _mm_sha1rnds4_epu32::<1>(abcd, e0);
        let msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        let msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 36-39
        let e1 = _mm_sha1nexte_epu32(e1, msg1);
        let e0 = abcd;
        let msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        let abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
        let msg0 = _mm_sha1msg1_epu32(msg0, msg1);
        let msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 40-43
        let e0 = _mm_sha1nexte_epu32(e0, msg2);
        let e1 = abcd;
        let msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        let abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
        let msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        let msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 44-47
        let e1 = _mm_sha1nexte_epu32(e1, msg3);
        let e0 = abcd;
        let msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        let abcd = _mm_sha1rnds4_epu32::<2>(abcd, e1);
        let msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        let msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 48-51
        let e0 = _mm_sha1nexte_epu32(e0, msg0);
        let e1 = abcd;
        let msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        let abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
        let msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        let msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 52-55
        let e1 = _mm_sha1nexte_epu32(e1, msg1);
        let e0 = abcd;
        let msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        let abcd = _mm_sha1rnds4_epu32::<2>(abcd, e1);
        let msg0 = _mm_sha1msg1_epu32(msg0, msg1);
        let msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 56-59
        let e0 = _mm_sha1nexte_epu32(e0, msg2);
        let e1 = abcd;
        let msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        let abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
        let msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        let msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 60-63
        let e1 = _mm_sha1nexte_epu32(e1, msg3);
        let e0 = abcd;
        let msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        let abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);
        let msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        let msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 64-67
        let e0 = _mm_sha1nexte_epu32(e0, msg0);
        let e1 = abcd;
        let msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        let abcd = _mm_sha1rnds4_epu32::<3>(abcd, e0);
        let msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        let msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 68-71
        let e1 = _mm_sha1nexte_epu32(e1, msg1);
        let e0 = abcd;
        let msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        let abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);
        let msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 72-75
        let e0 = _mm_sha1nexte_epu32(e0, msg2);
        let e1 = abcd;
        let msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        let abcd = _mm_sha1rnds4_epu32::<3>(abcd, e0);

        // Rounds 76-79
        let e1 = _mm_sha1nexte_epu32(e1, msg3);
        let e0 = abcd;
        let abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);
        
        let abcd = _mm_shuffle_epi32(abcd, 0x1B);

        (abcd, e0)
    }

    fn cycle(mut v: [u32; 5], w: [u32; 80], i: usize) -> [u32; 5] {
        if i == 80 { return v }

        let t = modular_add(&[
            rotate_left(v[0], 5) as u32,
            f(v[1], v[2], v[3], i),
            v[4],
            K[i/20],
            w[i]
        ]);
        
        v[4] = v[3]; // e
        v[3] = v[2];
        v[2] = rotate_left(v[1], 30) as u32;
        v[1] = v[0];
        v[0] = t; //a
    
        cycle(v, w, i + 1)
    }

    fn compute_w(message: &[u8]) -> [u32; 80] {
        let mut w = [0u32; 80];
        for (i, chunk) in zip(0..16, message.chunks(4)) {
            w[i] = join_bytes_to_u32(chunk);
        }

        for i in 16..80 {
            w[i] = rotate_left(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1) as u32;
        }

        w
    }

    /// Returns a SHA1 digest of the message, each byte formatted as hexadecimal
    /// 
    /// This function should be used for generating hashes, because this is the most common format for them.
    /// 
    /// # Example
    /// ```ignore
    /// let digest = sha1::as_hex(b"abc");
    /// assert_eq!(digest, "a9993e364706816aba3e25717850c26c9cd0d89d");
    /// ```
    pub fn as_hex(message: &[u8]) -> String {
        of(message).iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

mod test {
    use super::*;

    #[test]
    fn sha256_empty_string() {
        let hash = sha256::as_hex(b"");
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn sha256_short_string() {
        let hash = sha256::as_hex(b"hi");
        assert_eq!(hash, "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4");
    }

    #[test]
    fn sha256_long_string() {
        let hash = sha256::as_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(hash, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    #[test]
    fn sha1_short_string() {
        let hash = sha1::as_hex(b"abc");
        assert_eq!(hash, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn sha1_long_string() {
        let hash = sha1::as_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(hash, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    }

    #[test]
    fn sha1_million() {
        let hash = sha1::as_hex(&[b'a'; 1_000_000]);
        assert_eq!(hash, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

}