//! The serialization an event id is the SHA-256 of (NIP-01):
//! `[0,"<pubkey>",<created_at>,<kind>,<tags>,"<content>"]`, byte for byte as
//! rust-nostr writes it (`serde_json::to_vec` of that tuple): no whitespace,
//! `"` and `\` escaped, control characters as `\b \t \n \f \r` or `\u00xx`,
//! everything else (`/`, DEL, non-ASCII) as plain UTF-8.
//!
//! It goes to a callback in pieces instead of into a buffer, so a SHA-256
//! engine hashes it as it is written: no allocation, and a string with nothing
//! to escape, as almost all content is, passes as one slice.

use crate::{simd, RawStr};

/// Small pieces gathered so the callback sees a few large ones; a long run
/// (most content) goes straight through.
struct Sink<F: FnMut(&[u8])> {
    out: F,
    buf: [u8; 128],
    len: usize,
}

impl<F: FnMut(&[u8])> Sink<F> {
    fn new(out: F) -> Self {
        Sink { out, buf: [0; 128], len: 0 }
    }

    #[inline]
    fn put(&mut self, b: &[u8]) {
        if b.len() > self.buf.len() - self.len {
            self.flush();
            if b.len() >= self.buf.len() / 2 {
                (self.out)(b);
                return;
            }
        }
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
    }

    fn flush(&mut self) {
        if self.len > 0 {
            (self.out)(&self.buf[..self.len]);
            self.len = 0;
        }
    }

    fn number(&mut self, mut n: u64) {
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        loop {
            at -= 1;
            digits[at] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        self.put(&digits[at..]);
    }

    fn hex(&mut self, bytes: &[u8; 32]) {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; 64];
        for (i, &b) in bytes.iter().enumerate() {
            out[2 * i] = DIGITS[(b >> 4) as usize];
            out[2 * i + 1] = DIGITS[(b & 15) as usize];
        }
        self.put(&out);
    }

    /// One character that must be escaped: `"`, `\` or a control character.
    fn escape(&mut self, c: u8) {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        match c {
            b'"' => self.put(b"\\\""),
            b'\\' => self.put(b"\\\\"),
            0x08 => self.put(b"\\b"),
            b'\t' => self.put(b"\\t"),
            b'\n' => self.put(b"\\n"),
            0x0C => self.put(b"\\f"),
            b'\r' => self.put(b"\\r"),
            _ => self.put(&[b'\\', b'u', b'0', b'0', DIGITS[(c >> 4) as usize], DIGITS[(c & 15) as usize]]),
        }
    }

    /// A decoded string, quoted and escaped.
    fn string(&mut self, s: &[u8]) {
        self.put(b"\"");
        let mut from = 0;
        let mut i = 0;
        while i < s.len() {
            if i + 16 <= s.len() {
                let block: [u8; 16] = s[i..i + 16].try_into().expect("16 bytes");
                let m = simd::special_mask(block);
                if m == 0 {
                    i += 16;
                    continue;
                }
                i += simd::first_of(m);
            } else if !matches!(s[i], b'"' | b'\\' | 0..=0x1F) {
                i += 1;
                continue;
            }
            self.put(&s[from..i]);
            self.escape(s[i]);
            i += 1;
            from = i;
        }
        self.put(&s[from..]);
        self.put(b"\"");
    }

    /// A string as written in JSON, quoted and escaped the canonical way. False
    /// for a lone surrogate escape, which no UTF-8 string can hold.
    fn raw_string(&mut self, raw: RawStr<'_>) -> bool {
        let b = raw.bytes;
        if !raw.escaped {
            // Unescaped JSON text holds no `"`, `\` or control character: it is
            // already canonical.
            self.put(b"\"");
            self.put(b);
            self.put(b"\"");
            return true;
        }
        self.put(b"\"");
        let mut from = 0;
        let mut i = 0;
        while i < b.len() {
            if b[i] != b'\\' {
                i += 1;
                continue;
            }
            self.put(&b[from..i]);
            let len = match b.get(i + 1) {
                Some(b'u') => {
                    let Some(unit) = crate::hex4(b, i + 2) else { return false };
                    let (cp, len) = match unit {
                        0xD800..=0xDBFF => match (b.get(i + 6..i + 8), crate::hex4(b, i + 8)) {
                            (Some(b"\\u"), Some(low @ 0xDC00..=0xDFFF)) => (0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00), 12),
                            _ => return false,
                        },
                        0xDC00..=0xDFFF => return false,
                        _ => (unit, 6),
                    };
                    match cp {
                        0..=0x1F | 0x22 | 0x5C => self.escape(cp as u8),
                        _ => {
                            let mut utf8 = [0u8; 4];
                            let ch = char::from_u32(cp).expect("a scalar value: surrogates are handled above");
                            self.put(ch.encode_utf8(&mut utf8).as_bytes());
                        }
                    }
                    len
                }
                Some(b'/') => {
                    self.put(b"/");
                    2
                }
                // `\" \\ \b \f \n \r \t` are already canonical.
                Some(_) => {
                    self.put(&b[i..i + 2]);
                    2
                }
                None => return false,
            };
            i += len;
            from = i;
        }
        self.put(&b[from..]);
        self.put(b"\"");
        true
    }

    fn head(&mut self, pubkey: &[u8; 32], created_at: u64, kind: u16) {
        self.put(b"[0,\"");
        self.hex(pubkey);
        self.put(b"\",");
        self.number(created_at);
        self.put(b",");
        self.number(u64::from(kind));
        self.put(b",[");
    }
}

/// The NIP-01 serialization of an event with these fields, the bytes whose
/// SHA-256 is its id, handed to `out` in pieces. Feed them to a SHA-256 engine
/// and compare the digest with the event's id to check it:
///
/// ```
/// let mut bytes = Vec::new();
/// nostr_parse::write_preimage(&[0u8; 32], 1, 1, [["t", "nostr"]], "hi \"you\"", |piece| bytes.extend_from_slice(piece));
/// let expected = format!("[0,\"{}\",1,1,[[\"t\",\"nostr\"]],\"hi \\\"you\\\"\"]", "00".repeat(32));
/// assert_eq!(bytes, expected.as_bytes());
/// ```
///
/// [`Event::write_preimage`](crate::Event::write_preimage) and its siblings
/// call this with their own fields; this takes them from any representation.
pub fn write_preimage<'s, T, I>(pubkey: &[u8; 32], created_at: u64, kind: u16, tags: T, content: &str, out: impl FnMut(&[u8]))
where
    T: IntoIterator<Item = I>,
    I: IntoIterator<Item = &'s str>,
{
    let mut sink = Sink::new(out);
    sink.head(pubkey, created_at, kind);
    for (i, tag) in tags.into_iter().enumerate() {
        sink.put(if i == 0 { b"[" } else { b",[" });
        for (j, field) in tag.into_iter().enumerate() {
            if j > 0 {
                sink.put(b",");
            }
            sink.string(field.as_bytes());
        }
        sink.put(b"]");
    }
    sink.put(b"],");
    sink.string(content.as_bytes());
    sink.put(b"]");
    sink.flush();
}

/// [`write_preimage`] from strings as written, escapes and all. False when a
/// string holds a lone surrogate escape: valid JSON, but no event can carry it
/// (rust-nostr refuses one), and what was written so far is not a preimage.
pub(crate) fn write_raw_preimage<'a>(
    pubkey: &[u8; 32],
    created_at: u64,
    kind: u16,
    tags: impl Iterator<Item = impl Iterator<Item = RawStr<'a>>>,
    content: RawStr<'_>,
    out: impl FnMut(&[u8]),
) -> bool {
    let mut sink = Sink::new(out);
    sink.head(pubkey, created_at, kind);
    for (i, tag) in tags.enumerate() {
        sink.put(if i == 0 { b"[" } else { b",[" });
        for (j, field) in tag.enumerate() {
            if j > 0 {
                sink.put(b",");
            }
            if !sink.raw_string(field) {
                return false;
            }
        }
        sink.put(b"]");
    }
    sink.put(b"],");
    if !sink.raw_string(content) {
        return false;
    }
    sink.put(b"]");
    sink.flush();
    true
}
