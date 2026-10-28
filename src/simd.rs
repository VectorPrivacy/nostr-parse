//! The two byte-level kernels everything else stands on: finding the next byte a
//! JSON string cares about, and decoding lowercase hex into bytes.

const LO: u64 = 0x0101_0101_0101_0101;
const HI: u64 = 0x8080_8080_8080_8080;

/// Index of the first `"`, `\` or control byte (< 0x20) at or after `from`, or
/// `b.len()` when there is none.
#[inline(always)]
pub fn find_special(b: &[u8], from: usize) -> usize {
    let mut i = from;
    // SAFETY: each kernel reads only whole blocks inside `b`.
    #[cfg(target_arch = "aarch64")]
    match unsafe { special_neon(b, i) } {
        Ok(at) => return at,
        Err(resume) => i = resume,
    }
    #[cfg(target_arch = "x86_64")]
    match unsafe { special_sse2(b, i) } {
        Ok(at) => return at,
        Err(resume) => i = resume,
    }
    while i + 8 <= b.len() {
        let v = u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let q = v ^ (LO * b'"' as u64);
        let s = v ^ (LO * b'\\' as u64);
        let m = ((q.wrapping_sub(LO) & !q) | (s.wrapping_sub(LO) & !s) | (v.wrapping_sub(LO * 0x20) & !v)) & HI;
        if m != 0 {
            return i + (m.trailing_zeros() / 8) as usize;
        }
        i += 8;
    }
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\\' || c < 0x20 {
            return i;
        }
        i += 1;
    }
    b.len()
}

/// `Ok(index)` of the first special byte, or `Err(resume)` where fewer than 16
/// bytes remain unscanned.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn special_neon(b: &[u8], mut i: usize) -> Result<usize, usize> {
    use std::arch::aarch64::*;
    // SAFETY: every load is of 16 bytes starting at most 16 before the end.
    unsafe {
        let quote = vdupq_n_u8(b'"');
        let slash = vdupq_n_u8(b'\\');
        let ctl = vdupq_n_u8(0x20);
        while i + 16 <= b.len() {
            let v = vld1q_u8(b.as_ptr().add(i));
            let hit = vorrq_u8(vorrq_u8(vceqq_u8(v, quote), vceqq_u8(v, slash)), vcltq_u8(v, ctl));
            // Narrow each 0xFF/0x00 byte to a nibble: a 64-bit mask, 4 bits a byte.
            let m = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(hit), 4)), 0);
            if m != 0 {
                return Ok(i + (m.trailing_zeros() / 4) as usize);
            }
            i += 16;
        }
    }
    Err(i)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn special_sse2(b: &[u8], mut i: usize) -> Result<usize, usize> {
    use std::arch::x86_64::*;
    // SAFETY: SSE2 is part of x86_64; every load is of 16 bytes inside `b`.
    unsafe {
        let quote = _mm_set1_epi8(b'"' as i8);
        let slash = _mm_set1_epi8(b'\\' as i8);
        let ctl = _mm_set1_epi8(0x1F);
        while i + 16 <= b.len() {
            let v = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);
            // v <= 0x1F (unsigned) exactly when min(v, 0x1F) == v.
            let low = _mm_cmpeq_epi8(_mm_min_epu8(v, ctl), v);
            let hit = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(v, quote), _mm_cmpeq_epi8(v, slash)), low);
            let m = _mm_movemask_epi8(hit) as u32;
            if m != 0 {
                return Ok(i + m.trailing_zeros() as usize);
            }
            i += 16;
        }
    }
    Err(i)
}

/// Which of the 16 bytes in `v` are `"`, `\` or control bytes, as a mask that
/// is 0 when none is; [`first_of`] reads the first one's position from it. It
/// takes the bytes already loaded, so a caller that copies the block is not
/// made to load it twice, and returns the mask rather than a position, so a
/// caller can branch on "none" and move on 16 bytes without waiting for it.
#[inline(always)]
pub fn special_mask(v: [u8; 16]) -> u64 {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: NEON is baseline on aarch64; `v` is 16 bytes.
    unsafe {
        use std::arch::aarch64::*;
        let v = vld1q_u8(v.as_ptr());
        let hit = vorrq_u8(vorrq_u8(vceqq_u8(v, vdupq_n_u8(b'"')), vceqq_u8(v, vdupq_n_u8(b'\\'))), vcltq_u8(v, vdupq_n_u8(0x20)));
        // Narrow each 0xFF/0x00 byte to a nibble: 4 bits a byte.
        vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(hit), 4)), 0)
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SSE2 is part of x86_64; `v` is 16 bytes.
    unsafe {
        use std::arch::x86_64::*;
        let v = _mm_loadu_si128(v.as_ptr() as *const __m128i);
        let ctl = _mm_set1_epi8(0x1F);
        let low = _mm_cmpeq_epi8(_mm_min_epu8(v, ctl), v);
        let hit = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(v, _mm_set1_epi8(b'"' as i8)), _mm_cmpeq_epi8(v, _mm_set1_epi8(b'\\' as i8))), low);
        _mm_movemask_epi8(hit) as u32 as u64
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        v.iter().enumerate().fold(0u64, |m, (i, &c)| m | (u64::from(c == b'"' || c == b'\\' || c < 0x20) << i))
    }
}

/// The position of the first special byte a non-zero [`special_mask`] marks.
#[inline(always)]
pub fn first_of(mask: u64) -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        (mask.trailing_zeros() / 4) as usize
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        mask.trailing_zeros() as usize
    }
}

/// Lowercase hex digit → nibble; 0xFF for anything else.
static NIBBLE: [u8; 256] = {
    let mut t = [0xFFu8; 256];
    let mut i = 0;
    while i < 10 {
        t[b'0' as usize + i] = i as u8;
        i += 1;
    }
    let mut i = 0;
    while i < 6 {
        t[b'a' as usize + i] = 10 + i as u8;
        i += 1;
    }
    t
};

/// Decodes `2 * out.len()` lowercase hex digits from the start of `src` into
/// `out`; false when one of them is not a lowercase hex digit. `out.len()` is a
/// multiple of 16 (an id or key is 32 bytes, a signature 64).
#[inline(always)]
pub fn decode_hex(src: &[u8], out: &mut [u8]) -> bool {
    debug_assert!(out.len().is_multiple_of(16));
    let src = &src[..out.len() * 2];
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON is baseline on aarch64; blocks stay inside both slices.
        unsafe { hex_neon(src, out) }
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: SSE2 is part of x86_64; blocks stay inside both slices.
        unsafe { hex_sse2(src, out) }
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        hex_scalar(src, out)
    }
}

#[cfg_attr(any(target_arch = "aarch64", target_arch = "x86_64"), allow(dead_code))]
#[inline(always)]
fn hex_scalar(src: &[u8], out: &mut [u8]) -> bool {
    let mut bad = 0u8;
    for (o, pair) in out.iter_mut().zip(src.chunks_exact(2)) {
        let (hi, lo) = (NIBBLE[pair[0] as usize], NIBBLE[pair[1] as usize]);
        // One branch for the whole value: a bad digit sets the high bit.
        bad |= hi | lo;
        *o = (hi << 4) | (lo & 0x0F);
    }
    bad & 0x80 == 0
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn hex_neon(src: &[u8], out: &mut [u8]) -> bool {
    use std::arch::aarch64::*;
    // SAFETY: src holds 2 * out.len() bytes and out.len() is a multiple of 16, so
    // every 32-byte load and 16-byte store is in bounds.
    unsafe {
        let (zero, nine, a, five, ten) = (vdupq_n_u8(b'0'), vdupq_n_u8(9), vdupq_n_u8(b'a'), vdupq_n_u8(5), vdupq_n_u8(10));
        let mut ok = vdupq_n_u8(0xFF);
        let mut i = 0;
        while i < out.len() {
            // De-interleaved on load: even digits (high nibbles), odd digits.
            let pair = vld2q_u8(src.as_ptr().add(i * 2));
            let nib = |v: uint8x16_t, ok: &mut uint8x16_t| {
                let d = vsubq_u8(v, zero);
                let is_digit = vcleq_u8(d, nine);
                let l = vsubq_u8(v, a);
                let is_letter = vcleq_u8(l, five);
                *ok = vandq_u8(*ok, vorrq_u8(is_digit, is_letter));
                vbslq_u8(is_digit, d, vaddq_u8(l, ten))
            };
            let hi = nib(pair.0, &mut ok);
            let lo = nib(pair.1, &mut ok);
            vst1q_u8(out.as_mut_ptr().add(i), vorrq_u8(vshlq_n_u8(hi, 4), lo));
            i += 16;
        }
        vminvq_u8(ok) == 0xFF
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn hex_sse2(src: &[u8], out: &mut [u8]) -> bool {
    use std::arch::x86_64::*;
    // SAFETY: as in hex_neon; SSE2 only.
    unsafe {
        let (zero, nine, a, five, ten) = (
            _mm_set1_epi8(b'0' as i8),
            _mm_set1_epi8(9),
            _mm_set1_epi8(b'a' as i8),
            _mm_set1_epi8(5),
            _mm_set1_epi8(10),
        );
        let low_byte = _mm_set1_epi16(0x00FF);
        let mut ok = _mm_set1_epi8(-1);
        let nib = |v: __m128i, ok: &mut __m128i| {
            let d = _mm_sub_epi8(v, zero);
            let is_digit = _mm_cmpeq_epi8(_mm_min_epu8(d, nine), d);
            let l = _mm_sub_epi8(v, a);
            let is_letter = _mm_cmpeq_epi8(_mm_min_epu8(l, five), l);
            *ok = _mm_and_si128(*ok, _mm_or_si128(is_digit, is_letter));
            _mm_or_si128(_mm_and_si128(is_digit, d), _mm_andnot_si128(is_digit, _mm_add_epi8(l, ten)))
        };
        let mut i = 0;
        while i < out.len() {
            // 32 digits → 16 bytes: each 16-bit lane holds (high digit, low digit).
            let n0 = nib(_mm_loadu_si128(src.as_ptr().add(i * 2) as *const __m128i), &mut ok);
            let n1 = nib(_mm_loadu_si128(src.as_ptr().add(i * 2 + 16) as *const __m128i), &mut ok);
            let join = |n: __m128i| _mm_or_si128(_mm_slli_epi16(_mm_and_si128(n, low_byte), 4), _mm_srli_epi16(n, 8));
            _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, _mm_packus_epi16(join(n0), join(n1)));
            i += 16;
        }
        _mm_movemask_epi8(ok) == 0xFFFF
    }
}

/// `src` as lowercase hex, appended to `out`.
pub fn encode_hex(src: &[u8], out: &mut String) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    out.reserve(src.len() * 2);
    for &b in src {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0F) as usize] as char);
    }
}
