//! Parses one Nostr event, as NIP-01 JSON, into an owned [`Event`].
//!
//! Strict: the text must be one JSON object holding the seven NIP-01 fields
//! once each (other keys are checked and skipped), id and pubkey as 64
//! lowercase hex digits, sig as 128 (or `""`, an unsigned event such as a
//! NIP-59 rumor), created_at and kind as plain non-negative integers, tags as
//! arrays of strings. Strings are fully unescaped; a lone surrogate is refused.
//!
//! Fast where events spend their time: string ends are found 16 bytes at a time,
//! hex is decoded 32 digits at a time straight into byte arrays (no strings for
//! id, pubkey or sig), and every string, tag and the tag list is allocated once,
//! at its exact size, with no growth along the way.
//!
//! Two shapes of the same event: [`Event`] keeps tags as `Vec<Vec<String>>`, what
//! other Nostr libraries hold (rust-nostr's `Tag` is that list); [`CompactEvent`]
//! keeps every tag's text in one buffer with one index beside it ([`Tags`]), so
//! an event costs at most three allocations however many tags it has.

mod simd;

use std::fmt;

pub use simd::encode_hex;

/// A Nostr event that owns its data. `T` is how it keeps its tags: lists of
/// `String`s by default, or [`Tags`] for a [`CompactEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Event<T = Vec<Vec<String>>> {
    pub id: [u8; 32],
    pub pubkey: [u8; 32],
    pub created_at: u64,
    pub kind: u16,
    pub tags: T,
    pub content: String,
    /// `None` for an unsigned event, whose sig is `""`.
    pub sig: Option<[u8; 64]>,
}

/// An event whose tags' text is all in one buffer: see [`Tags`].
pub type CompactEvent = Event<Tags>;

/// Tags as lists of strings, their text kept in one buffer (every field back to
/// back, fully unescaped) with one index of where each field and each tag ends:
/// two allocations for any number of tags, against one per tag and one per
/// field for `Vec<Vec<String>>`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Tags {
    text: Box<str>,
    /// `ntags` tag ends (each a count of fields so far), then each field's end in `text`.
    index: Box<[u32]>,
    ntags: u32,
}

impl Tags {
    /// How many tags.
    pub fn len(&self) -> usize {
        self.ntags as usize
    }

    pub fn is_empty(&self) -> bool {
        self.ntags == 0
    }

    /// Tag `i`.
    pub fn get(&self, i: usize) -> Option<Tag<'_>> {
        let (tag_ends, field_ends) = self.index.split_at(self.len());
        let last = *tag_ends.get(i)? as usize;
        let first = if i == 0 { 0 } else { tag_ends[i - 1] as usize };
        let start = if first == 0 { 0 } else { field_ends[first - 1] };
        Some(Tag { text: &self.text, ends: &field_ends[first..last], start })
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = Tag<'_>> + '_ {
        (0..self.len()).map(|i| self.get(i).expect("i < len"))
    }

    /// The tags as owned lists, as an [`Event`] holds them.
    pub fn to_vecs(&self) -> Vec<Vec<String>> {
        self.iter().map(|t| t.to_vec()).collect()
    }
}

impl fmt::Debug for Tags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// One tag of a [`Tags`]: its fields as `&str`.
#[derive(Clone, Copy)]
pub struct Tag<'a> {
    text: &'a str,
    /// Each field's end in `text`; the first starts at `start`.
    ends: &'a [u32],
    start: u32,
}

impl<'a> Tag<'a> {
    /// How many fields.
    pub fn len(&self) -> usize {
        self.ends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    /// Field `j`.
    pub fn get(&self, j: usize) -> Option<&'a str> {
        let end = *self.ends.get(j)? as usize;
        let start = if j == 0 { self.start } else { self.ends[j - 1] } as usize;
        // SAFETY: every field end is the end of a whole UTF-8 string written by
        // the parser, so both are char boundaries of `text`, and start <= end.
        Some(unsafe { self.text.get_unchecked(start..end) })
    }

    /// The first field, as in `["e", ...]`.
    pub fn name(&self) -> Option<&'a str> {
        self.get(0)
    }

    /// The fields, borrowing the event rather than this `Tag`.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &'a str> + use<'a> {
        let tag = *self;
        (0..tag.len()).map(move |j| tag.get(j).expect("j < len"))
    }

    pub fn to_vec(&self) -> Vec<String> {
        self.iter().map(str::to_owned).collect()
    }
}

impl fmt::Debug for Tag<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub msg: &'static str,
    /// Byte offset in the input where parsing stopped.
    pub pos: usize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.msg, self.pos)
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

/// Parses one event. A [`Parser`] kept across events saves a little more.
pub fn parse(json: &str) -> Result<Event> {
    Parser::new().parse(json)
}

/// Parses one event into a [`CompactEvent`].
pub fn parse_compact(json: &str) -> Result<CompactEvent> {
    Parser::new().parse_compact(json)
}

/// Reusable scratch space: tags are gathered here and then moved or copied into
/// exactly the right size, and escaped strings are unescaped here and then copied
/// out at their size, so nothing the event keeps is ever reallocated.
#[derive(Default)]
pub struct Parser {
    lists: Lists,
    packed: Packed,
    esc: Vec<u8>,
}

/// Scratch for [`Event`]'s tags.
#[derive(Default)]
struct Lists {
    fields: Vec<String>,
    tags: Vec<Vec<String>>,
}

/// Scratch for [`CompactEvent`]'s tags: [`Tags`] in the making.
#[derive(Default)]
struct Packed {
    text: Vec<u8>,
    fields: Vec<u32>,
    tag_ends: Vec<u32>,
}

/// How a parse reads `tags`, so one parse serves both event shapes.
trait TagRead {
    type Tags: Default;
    fn read(&mut self, c: &mut Cur<'_>) -> Result<Self::Tags>;
}

impl TagRead for Lists {
    type Tags = Vec<Vec<String>>;
    #[inline(always)]
    fn read(&mut self, c: &mut Cur<'_>) -> Result<Self::Tags> {
        self.tags(c)
    }
}

impl TagRead for Packed {
    type Tags = Tags;
    #[inline(always)]
    fn read(&mut self, c: &mut Cur<'_>) -> Result<Self::Tags> {
        self.tags(c)
    }
}

/// Nesting allowed inside a skipped value (an unknown key's).
const MAX_DEPTH: u32 = 64;

const ID: u8 = 1;
const PUBKEY: u8 = 2;
const CREATED_AT: u8 = 4;
const KIND: u8 = 8;
const TAGS: u8 = 16;
const CONTENT: u8 = 32;
const SIG: u8 = 64;
const ALL: u8 = 127;

impl Parser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(&mut self, json: &str) -> Result<Event> {
        parse_with(&mut self.lists, &mut self.esc, json)
    }

    pub fn parse_compact(&mut self, json: &str) -> Result<CompactEvent> {
        parse_with(&mut self.packed, &mut self.esc, json)
    }
}

#[inline(always)]
fn parse_with<R: TagRead>(tags: &mut R, esc: &mut Vec<u8>, json: &str) -> Result<Event<R::Tags>> {
    match canonical(tags, esc, json) {
        Some(ev) => Ok(ev),
        None => general(tags, esc, json),
    }
}

/// The layout relays and clients write: NIP-01's field order, no whitespace.
/// Each key and its punctuation is one fixed compare; anything else (another
/// order, whitespace, an extra key, an error) is left to [`general`], which
/// reads any layout and names the error.
#[inline(always)]
fn canonical<R: TagRead>(reader: &mut R, esc: &mut Vec<u8>, json: &str) -> Option<Event<R::Tags>> {
    let mut c = Cur { s: json, b: json.as_bytes(), p: 0, esc };
    let (mut id, mut pubkey) = ([0u8; 32], [0u8; 32]);
    c.lit(b"{\"id\":")?;
    c.hex(&mut id, "").ok()?;
    c.lit(b",\"pubkey\":")?;
    c.hex(&mut pubkey, "").ok()?;
    c.lit(b",\"created_at\":")?;
    let created_at = c.uint().ok()?;
    c.lit(b",\"kind\":")?;
    let kind = u16::try_from(c.uint().ok()?).ok()?;
    c.lit(b",\"tags\":")?;
    let tags = reader.read(&mut c).ok()?;
    c.lit(b",\"content\":")?;
    let content = c.string().ok()?;
    c.lit(b",\"sig\":")?;
    let sig = c.sig().ok()?;
    c.lit(b"}")?;
    (c.p == c.b.len()).then_some(Event { id, pubkey, created_at, kind, tags, content, sig })
}

fn general<R: TagRead>(reader: &mut R, esc: &mut Vec<u8>, json: &str) -> Result<Event<R::Tags>> {
    let mut c = Cur { s: json, b: json.as_bytes(), p: 0, esc };
    let mut ev = Event::default();
    let mut seen = 0u8;
    c.ws();
    c.expect(b'{', "expected '{'")?;
    c.ws();
    if c.peek() != Some(b'}') {
        loop {
            c.ws();
            let key = c.key()?;
            c.ws();
            c.expect(b':', "expected ':'")?;
            c.ws();
            let bit = match key {
                Key::Id => {
                    c.hex(&mut ev.id, "id must be 64 lowercase hex digits")?;
                    ID
                }
                Key::Pubkey => {
                    c.hex(&mut ev.pubkey, "pubkey must be 64 lowercase hex digits")?;
                    PUBKEY
                }
                Key::CreatedAt => {
                    ev.created_at = c.uint()?;
                    CREATED_AT
                }
                Key::Kind => {
                    let p = c.p;
                    ev.kind = u16::try_from(c.uint()?).map_err(|_| Error { msg: "kind out of range", pos: p })?;
                    KIND
                }
                Key::Tags => {
                    ev.tags = reader.read(&mut c)?;
                    TAGS
                }
                Key::Content => {
                    ev.content = c.string()?;
                    CONTENT
                }
                Key::Sig => {
                    ev.sig = c.sig()?;
                    SIG
                }
                Key::Other => {
                    c.skip(0)?;
                    0
                }
            };
            if seen & bit != 0 {
                return c.err("duplicate key");
            }
            seen |= bit;
            c.ws();
            match c.next() {
                Some(b',') => {}
                Some(b'}') => break,
                _ => return c.err_back("expected ',' or '}'"),
            }
        }
    } else {
        c.p += 1;
    }
    if seen != ALL {
        return c.err(missing(seen));
    }
    c.ws();
    if c.p != c.b.len() {
        return c.err("trailing characters");
    }
    Ok(ev)
}

impl Lists {
    /// `[["e", "…"], …]`: each field is collected in `self.fields`, each tag in
    /// `self.tags`, and both are moved into exact-size lists at the end.
    fn tags(&mut self, c: &mut Cur<'_>) -> Result<Vec<Vec<String>>> {
        c.expect(b'[', "tags must be an array")?;
        c.ws();
        if c.peek() == Some(b']') {
            c.p += 1;
            return Ok(Vec::new());
        }
        self.tags.clear();
        loop {
            c.ws();
            c.expect(b'[', "a tag must be an array")?;
            c.ws();
            self.fields.clear();
            if c.peek() == Some(b']') {
                c.p += 1;
            } else {
                loop {
                    c.ws();
                    self.fields.push(c.string()?);
                    c.ws();
                    match c.next() {
                        Some(b',') => {}
                        Some(b']') => break,
                        _ => return c.err_back("expected ',' or ']' in a tag"),
                    }
                }
            }
            self.tags.push(take_exact(&mut self.fields));
            c.ws();
            match c.next() {
                Some(b',') => {}
                Some(b']') => break,
                _ => return c.err_back("expected ',' or ']' after a tag"),
            }
        }
        Ok(take_exact(&mut self.tags))
    }
}

impl Packed {
    /// `[["e", "…"], …]`: every field's text appended to `self.text`, its end
    /// noted in `self.fields`, each tag's end in `self.tag_ends`; then the text
    /// and one index copied out at their exact size.
    fn tags(&mut self, c: &mut Cur<'_>) -> Result<Tags> {
        c.expect(b'[', "tags must be an array")?;
        c.ws();
        if c.peek() == Some(b']') {
            c.p += 1;
            return Ok(Tags::default());
        }
        self.text.clear();
        self.fields.clear();
        self.tag_ends.clear();
        loop {
            c.ws();
            c.expect(b'[', "a tag must be an array")?;
            c.ws();
            if c.peek() == Some(b']') {
                c.p += 1;
            } else {
                loop {
                    c.ws();
                    c.string_into(&mut self.text)?;
                    self.fields.push(self.text.len() as u32);
                    c.ws();
                    match c.next() {
                        Some(b',') => {}
                        Some(b']') => break,
                        _ => return c.err_back("expected ',' or ']' in a tag"),
                    }
                }
            }
            self.tag_ends.push(self.fields.len() as u32);
            c.ws();
            match c.next() {
                Some(b',') => {}
                Some(b']') => break,
                _ => return c.err_back("expected ',' or ']' after a tag"),
            }
        }
        if self.text.len() > u32::MAX as usize {
            return c.err("tags hold more than 4 GiB of text");
        }
        let mut index = Vec::with_capacity(self.tag_ends.len() + self.fields.len());
        index.extend_from_slice(&self.tag_ends);
        index.extend_from_slice(&self.fields);
        // SAFETY: whole UTF-8 strings back to back.
        let text: Box<str> = unsafe { std::str::from_utf8_unchecked(&self.text) }.into();
        Ok(Tags { text, index: index.into_boxed_slice(), ntags: self.tag_ends.len() as u32 })
    }
}

fn missing(seen: u8) -> &'static str {
    match !seen & ALL {
        m if m & ID != 0 => "missing id",
        m if m & PUBKEY != 0 => "missing pubkey",
        m if m & CREATED_AT != 0 => "missing created_at",
        m if m & KIND != 0 => "missing kind",
        m if m & TAGS != 0 => "missing tags",
        m if m & CONTENT != 0 => "missing content",
        _ => "missing sig",
    }
}

enum Key {
    Id,
    Pubkey,
    CreatedAt,
    Kind,
    Tags,
    Content,
    Sig,
    Other,
}

/// A cursor over the input. `s` and `b` are the same text; `s` is kept so a
/// string with no escapes can be copied out without checking its UTF-8 again.
struct Cur<'a> {
    s: &'a str,
    b: &'a [u8],
    p: usize,
    /// The parser's buffer for unescaping.
    esc: &'a mut Vec<u8>,
}

impl Cur<'_> {
    #[cold]
    fn err<T>(&self, msg: &'static str) -> Result<T> {
        Err(Error { msg, pos: self.p })
    }

    /// An error about the byte just consumed.
    #[cold]
    fn err_back<T>(&self, msg: &'static str) -> Result<T> {
        Err(Error { msg, pos: self.p.saturating_sub(1) })
    }

    #[inline(always)]
    fn peek(&self) -> Option<u8> {
        self.b.get(self.p).copied()
    }

    #[inline(always)]
    fn next(&mut self) -> Option<u8> {
        let c = self.b.get(self.p).copied();
        self.p += 1;
        c
    }

    #[inline(always)]
    fn ws(&mut self) {
        // Events off a relay have no whitespace: one compare and out.
        while let Some(&c) = self.b.get(self.p) {
            if c > b' ' || !(c == b' ' || c == b'\n' || c == b'\r' || c == b'\t') {
                break;
            }
            self.p += 1;
        }
    }

    #[inline(always)]
    fn expect(&mut self, c: u8, msg: &'static str) -> Result<()> {
        if self.peek() == Some(c) {
            self.p += 1;
            Ok(())
        } else {
            self.err(msg)
        }
    }

    /// An object key, quotes included.
    #[inline(always)]
    fn key(&mut self) -> Result<Key> {
        self.expect(b'"', "expected a key")?;
        let start = self.p;
        let end = simd::find_special(self.b, start);
        if self.b.get(end) != Some(&b'"') {
            // An escaped key (or a broken one): unescape it and compare.
            self.p -= 1;
            let k = self.string()?;
            return Ok(key_of(k.as_bytes()));
        }
        self.p = end + 1;
        Ok(key_of(&self.b[start..end]))
    }

    /// Consumes `s` if the input continues with exactly it.
    #[inline(always)]
    fn lit(&mut self, s: &[u8]) -> Option<()> {
        let end = self.p + s.len();
        (self.b.get(self.p..end) == Some(s)).then(|| self.p = end)
    }

    /// 128 hex digits, or `""` for an unsigned event.
    #[inline(always)]
    fn sig(&mut self) -> Result<Option<[u8; 64]>> {
        if self.lit(b"\"\"").is_some() {
            return Ok(None);
        }
        let mut sig = [0u8; 64];
        self.hex(&mut sig, "sig must be 128 lowercase hex digits or empty")?;
        Ok(Some(sig))
    }

    /// A string of exactly `2 * out.len()` lowercase hex digits, decoded.
    #[inline(always)]
    fn hex(&mut self, out: &mut [u8], msg: &'static str) -> Result<()> {
        let n = out.len() * 2;
        let p = self.p;
        match self.b.get(p..p + n + 2) {
            Some(v) if v[0] == b'"' && v[n + 1] == b'"' && simd::decode_hex(&v[1..], out) => {
                self.p = p + n + 2;
                Ok(())
            }
            _ => self.err(msg),
        }
    }

    /// A non-negative integer in plain decimal: no sign, fraction, exponent or
    /// leading zero (an event id commits to the number's decimal text).
    #[inline(always)]
    fn uint(&mut self) -> Result<u64> {
        let start = self.p;
        let mut v: u64 = 0;
        while let Some(&c) = self.b.get(self.p) {
            let d = c.wrapping_sub(b'0');
            if d > 9 {
                break;
            }
            // Wraps only past 19 digits, which are re-read with checks below.
            v = v.wrapping_mul(10).wrapping_add(u64::from(d));
            self.p += 1;
        }
        let len = self.p - start;
        if len == 0 {
            return self.err("expected a non-negative integer");
        }
        if len > 19 {
            let digits = &self.b[start..self.p];
            v = digits
                .iter()
                .try_fold(0u64, |v, &c| v.checked_mul(10)?.checked_add(u64::from(c - b'0')))
                .ok_or(Error { msg: "number out of range", pos: start })?;
        }
        if len > 1 && self.b[start] == b'0' {
            return self.err("leading zero");
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return self.err("expected an integer");
        }
        Ok(v)
    }

    /// A string, unescaped, as an owned `String` allocated once at its size.
    #[inline(always)]
    fn string(&mut self) -> Result<String> {
        self.expect(b'"', "expected a string")?;
        let start = self.p;
        let end = simd::find_special(self.b, start);
        if self.b.get(end) == Some(&b'"') {
            self.p = end + 1;
            // SAFETY: `start` follows an ASCII quote and `end` is one, so both
            // are char boundaries of `s`.
            return Ok(owned(unsafe { self.s.get_unchecked(start..end) }));
        }
        self.escaped_string(start, end)
    }

    /// The rest of a string that has an escape (or a broken byte) at `at`:
    /// unescaped into the reused scratch buffer, then copied into a `String` of
    /// exactly its size.
    #[cold]
    #[inline(never)]
    fn escaped_string(&mut self, start: usize, at: usize) -> Result<String> {
        self.esc.clear();
        let end = unescape(self.b, start, at, self.esc)?;
        self.p = end + 1;
        // SAFETY: `unescape` writes only whole UTF-8.
        Ok(owned(unsafe { std::str::from_utf8_unchecked(self.esc) }))
    }

    /// A string, unescaped, appended to `out`.
    #[inline(always)]
    fn string_into(&mut self, out: &mut Vec<u8>) -> Result<()> {
        self.expect(b'"', "expected a string")?;
        let start = self.p;
        let end = simd::find_special(self.b, start);
        if self.b.get(end) == Some(&b'"') {
            self.p = end + 1;
            out.extend_from_slice(&self.b[start..end]);
            return Ok(());
        }
        self.escaped_into(start, end, out)
    }

    #[cold]
    #[inline(never)]
    fn escaped_into(&mut self, start: usize, at: usize, out: &mut Vec<u8>) -> Result<()> {
        let end = unescape(self.b, start, at, out)?;
        self.p = end + 1;
        Ok(())
    }


    /// Skips one value of any kind, checking it is valid JSON.
    fn skip(&mut self, depth: u32) -> Result<()> {
        if depth > MAX_DEPTH {
            return self.err("nested too deeply");
        }
        match self.peek() {
            Some(b'"') => {
                self.p += 1;
                let mut at = self.p;
                loop {
                    at = simd::find_special(self.b, at);
                    match self.b.get(at) {
                        Some(b'"') => break,
                        Some(b'\\') => {
                            at += match self.b.get(at + 1) {
                                Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => 2,
                                Some(b'u') if self.b.get(at + 2..at + 6).is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)) => 6,
                                _ => {
                                    self.p = at;
                                    return self.err("bad escape");
                                }
                            }
                        }
                        _ => {
                            self.p = at;
                            return self.err("bad string");
                        }
                    }
                }
                self.p = at + 1;
            }
            Some(b'{') => {
                self.p += 1;
                self.ws();
                if self.peek() == Some(b'}') {
                    self.p += 1;
                    return Ok(());
                }
                loop {
                    self.ws();
                    if self.peek() != Some(b'"') {
                        return self.err("expected a key");
                    }
                    self.skip(depth + 1)?;
                    self.ws();
                    self.expect(b':', "expected ':'")?;
                    self.ws();
                    self.skip(depth + 1)?;
                    self.ws();
                    match self.next() {
                        Some(b',') => {}
                        Some(b'}') => return Ok(()),
                        _ => return self.err_back("expected ',' or '}'"),
                    }
                }
            }
            Some(b'[') => {
                self.p += 1;
                self.ws();
                if self.peek() == Some(b']') {
                    self.p += 1;
                    return Ok(());
                }
                loop {
                    self.ws();
                    self.skip(depth + 1)?;
                    self.ws();
                    match self.next() {
                        Some(b',') => {}
                        Some(b']') => return Ok(()),
                        _ => return self.err_back("expected ',' or ']'"),
                    }
                }
            }
            Some(b't') => self.literal(b"true")?,
            Some(b'f') => self.literal(b"false")?,
            Some(b'n') => self.literal(b"null")?,
            Some(b'-' | b'0'..=b'9') => self.number()?,
            _ => return self.err("expected a value"),
        }
        Ok(())
    }

    fn literal(&mut self, word: &[u8]) -> Result<()> {
        if self.b.get(self.p..self.p + word.len()) == Some(word) {
            self.p += word.len();
            Ok(())
        } else {
            self.err("bad literal")
        }
    }

    /// Any JSON number, checked against the grammar.
    fn number(&mut self) -> Result<()> {
        let digits = |c: &mut Self| {
            let s = c.p;
            while c.peek().is_some_and(|b| b.is_ascii_digit()) {
                c.p += 1;
            }
            c.p - s
        };
        if self.peek() == Some(b'-') {
            self.p += 1;
        }
        let first = self.p;
        match digits(self) {
            0 => return self.err("bad number"),
            n if n > 1 && self.b[first] == b'0' => return self.err("leading zero"),
            _ => {}
        }
        if self.peek() == Some(b'.') {
            self.p += 1;
            if digits(self) == 0 {
                return self.err("bad number");
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.p += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.p += 1;
            }
            if digits(self) == 0 {
                return self.err("bad number");
            }
        }
        Ok(())
    }
}

/// The rest of a JSON string whose first special byte (an escape, or a broken
/// byte) is at `at`, unescaped in one pass onto the end of `out`; the string's
/// text began at `start`. Returns where its closing quote is.
fn unescape(b: &[u8], start: usize, at: usize, out: &mut Vec<u8>) -> Result<usize> {
    let base = out.len();
    // Unescaping only ever shrinks text, so the rest of the input bounds the
    // output; 16 more let every block be stored whole before it is checked.
    out.reserve(b.len() - start + 16);
    // SAFETY (all writes below): `o` never passes `i - start`, because every
    // escape is at least as long as what it stands for, and `i <= b.len()`; so
    // `base + o + 16` and `base + o + 4` stay inside the capacity reserved above.
    let dst = unsafe { out.as_mut_ptr().add(base) };
    unsafe { std::ptr::copy_nonoverlapping(b.as_ptr().add(start), dst, at - start) };
    let (mut i, mut o) = (at, at - start);
    loop {
        // Copy up to the next special byte, a block at a time: the block is
        // stored before it is checked, and only its clean part is kept.
        while i + 16 <= b.len() {
            // SAFETY: 16 bytes are readable at `i` and writable at `o`.
            let k = unsafe {
                let v = std::ptr::read_unaligned(b.as_ptr().add(i) as *const [u8; 16]);
                std::ptr::write_unaligned(dst.add(o) as *mut [u8; 16], v);
                simd::first_special16(b.as_ptr().add(i))
            };
            i += k;
            o += k;
            if k < 16 {
                break;
            }
        }
        if i + 16 > b.len() {
            while i < b.len() && !matches!(b[i], b'"' | b'\\' | 0..=0x1F) {
                // SAFETY: as above.
                unsafe { *dst.add(o) = b[i] };
                i += 1;
                o += 1;
            }
        }
        match b.get(i) {
            Some(b'"') => break,
            Some(b'\\') => {}
            Some(_) => {
                return Err(Error { msg: "control character in string", pos: i });
            }
            None => {
                return Err(Error { msg: "unterminated string", pos: i });
            }
        }
        let one = |c: u8| -> (u8, usize) { (c, 2) };
        let (c, len) = match b.get(i + 1) {
            Some(b'"') => one(b'"'),
            Some(b'\\') => one(b'\\'),
            Some(b'/') => one(b'/'),
            Some(b'b') => one(0x08),
            Some(b'f') => one(0x0C),
            Some(b'n') => one(b'\n'),
            Some(b'r') => one(b'\r'),
            Some(b't') => one(b'\t'),
            Some(b'u') => {
                let Some(unit) = hex4(b, i + 2) else {
                    return Err(Error { msg: "bad \\u escape", pos: i });
                };
                let (cp, len) = match unit {
                    0xD800..=0xDBFF => match (b.get(i + 6..i + 8), hex4(b, i + 8)) {
                        (Some(b"\\u"), Some(low @ 0xDC00..=0xDFFF)) => (0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00), 12),
                        _ => {
                            return Err(Error { msg: "lone surrogate", pos: i });
                        }
                    },
                    0xDC00..=0xDFFF => {
                        return Err(Error { msg: "lone surrogate", pos: i });
                    }
                    _ => (unit, 6),
                };
                let ch = char::from_u32(cp).expect("a scalar value: surrogates are handled above");
                let mut buf = [0u8; 4];
                let s = ch.encode_utf8(&mut buf).as_bytes();
                // SAFETY: as above; `s` is at most 4 bytes and shorter than `len`.
                unsafe { std::ptr::copy_nonoverlapping(s.as_ptr(), dst.add(o), s.len()) };
                o += s.len();
                i += len;
                continue;
            }
            _ => {
                return Err(Error { msg: "bad escape", pos: i });
            }
        };
        // SAFETY: as above.
        unsafe { *dst.add(o) = c };
        o += 1;
        i += len;
    }
    // SAFETY: the `o` bytes past `base` were written above: UTF-8 runs copied
    // whole from a `&str` (cut only at ASCII bytes), single ASCII bytes, and
    // UTF-8 encodings of scalar values.
    unsafe { out.set_len(base + o) };
    Ok(i)
}

/// `s` as a `String` of exactly its length. Most tag fields are a few bytes, so
/// those are copied with two overlapping loads and stores instead of a call to
/// `memcpy`.
#[inline(always)]
fn owned(s: &str) -> String {
    let n = s.len();
    if n == 0 {
        return String::new();
    }
    let mut v = Vec::<u8>::with_capacity(n);
    let (src, dst) = (s.as_ptr(), v.as_mut_ptr());
    // SAFETY: `src` holds `n` readable bytes and `dst` room for `n`; each pair of
    // accesses covers [0, n) without going past it, since n is at least the width.
    unsafe {
        use std::ptr::{read_unaligned as rd, write_unaligned as wr};
        match n {
            33..=64 => {
                // An id or key in a tag: four overlapping blocks.
                wr(dst as *mut [u8; 16], rd(src as *const [u8; 16]));
                wr(dst.add(16) as *mut [u8; 16], rd(src.add(16) as *const [u8; 16]));
                wr(dst.add(n - 32) as *mut [u8; 16], rd(src.add(n - 32) as *const [u8; 16]));
                wr(dst.add(n - 16) as *mut [u8; 16], rd(src.add(n - 16) as *const [u8; 16]));
            }
            16..=32 => {
                wr(dst as *mut [u8; 16], rd(src as *const [u8; 16]));
                wr(dst.add(n - 16) as *mut [u8; 16], rd(src.add(n - 16) as *const [u8; 16]));
            }
            8..=15 => {
                wr(dst as *mut u64, rd(src as *const u64));
                wr(dst.add(n - 8) as *mut u64, rd(src.add(n - 8) as *const u64));
            }
            4..=7 => {
                wr(dst as *mut u32, rd(src as *const u32));
                wr(dst.add(n - 4) as *mut u32, rd(src.add(n - 4) as *const u32));
            }
            1..=3 => {
                *dst = *src;
                *dst.add(n / 2) = *src.add(n / 2);
                *dst.add(n - 1) = *src.add(n - 1);
            }
            _ => std::ptr::copy_nonoverlapping(src, dst, n),
        }
        v.set_len(n);
        // SAFETY: a byte-for-byte copy of a `str`.
        String::from_utf8_unchecked(v)
    }
}

/// Moves everything out of `v` into a new `Vec` of exactly its length. Tags hold
/// two or three fields, so those are moved one by one rather than by a call to
/// `memcpy`.
#[inline(always)]
fn take_exact<T>(v: &mut Vec<T>) -> Vec<T> {
    let n = v.len();
    let mut out = Vec::<T>::with_capacity(n);
    // SAFETY: the `n` values are moved (read once, written once) into room for
    // `n`, and `v` forgets them before anything can observe it.
    unsafe {
        let (src, dst) = (v.as_ptr(), out.as_mut_ptr());
        v.set_len(0);
        match n {
            0 => {}
            1 => dst.write(src.read()),
            2 => {
                dst.write(src.read());
                dst.add(1).write(src.add(1).read());
            }
            3 => {
                dst.write(src.read());
                dst.add(1).write(src.add(1).read());
                dst.add(2).write(src.add(2).read());
            }
            _ => std::ptr::copy_nonoverlapping(src, dst, n),
        }
        out.set_len(n);
    }
    out
}

#[inline(always)]
fn key_of(k: &[u8]) -> Key {
    match k {
        b"id" => Key::Id,
        b"pubkey" => Key::Pubkey,
        b"created_at" => Key::CreatedAt,
        b"kind" => Key::Kind,
        b"tags" => Key::Tags,
        b"content" => Key::Content,
        b"sig" => Key::Sig,
        _ => Key::Other,
    }
}

/// The four hex digits (either case) at `at` as a number.
#[inline]
fn hex4(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)?.iter().try_fold(0u32, |v, &c| {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        Some((v << 4) | u32::from(d))
    })
}
