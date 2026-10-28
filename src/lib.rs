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
//! keeps its content, every tag's text and their index in one heap block, so an
//! event costs one allocation however many tags it has.
//!
//! And one read in place, for relays: [`Parser::parse_spans`] decodes id, pubkey
//! and sig and leaves every string as a [`RawStr`] of the input, as written,
//! with nothing unescaped or allocated.
//!
//! An unsigned event, such as a NIP-59 rumor, is read by
//! [`Parser::parse_unsigned`] into an [`UnsignedEvent`]: no `sig` needed (one
//! that is there is ignored, whatever it holds), and the id optional.
//!
//! Every shape can write its NIP-01 serialization, the bytes whose SHA-256 is
//! the event id, straight into a hasher with `write_preimage`, the same bytes
//! rust-nostr hashes, without building them first.

mod preimage;
mod simd;

pub use preimage::write_preimage;

use std::fmt;

pub use simd::encode_hex;

/// A Nostr event that owns its data.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Event {
    pub id: [u8; 32],
    pub pubkey: [u8; 32],
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    /// `None` for an unsigned event, whose sig is `""`.
    pub sig: Option<[u8; 64]>,
}

/// An event with no signature, such as a NIP-59 rumor: what rust-nostr calls an
/// `UnsignedEvent`, read by the same rules.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnsignedEvent {
    /// `None` when the event has no `id`, or `"id": null`.
    pub id: Option<[u8; 32]>,
    pub pubkey: [u8; 32],
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

/// A Nostr event whose content and tags live in one heap block: one allocation
/// however many tags it has (none for an event with no content and no tags),
/// read through [`Self::content`] and [`Self::tags`].
#[derive(Clone, PartialEq, Eq, Default)]
pub struct CompactEvent {
    pub id: [u8; 32],
    pub pubkey: [u8; 32],
    pub created_at: u64,
    pub kind: u16,
    /// `None` for an unsigned event, whose sig is `""`.
    pub sig: Option<[u8; 64]>,
    /// The sizes of `body`'s parts: content bytes, tags, fields.
    content_len: u32,
    tag_count: u32,
    field_count: u32,
    /// The index (each tag's end as a count of fields so far, then each field's
    /// end in the tag text, as `u32`s), the content, then the tag text (every
    /// field back to back). Empty for an event with no content and no tags.
    body: Box<[u8]>,
}

/// `u32`s as their bytes in memory, copied into a body as one block.
#[inline(always)]
fn bytes_of(v: &[u32]) -> &[u8] {
    // SAFETY: every byte of a u32 is a valid u8, and a u8 needs no alignment.
    unsafe { std::slice::from_raw_parts(v.as_ptr().cast::<u8>(), std::mem::size_of_val(v)) }
}

/// The `k`th `u32` of a body's index.
#[inline(always)]
fn word(body: &[u8], k: usize) -> usize {
    u32::from_ne_bytes(body[4 * k..4 * k + 4].try_into().expect("4 bytes")) as usize
}

impl Event {
    /// Its NIP-01 serialization, the bytes whose SHA-256 is its id, in pieces:
    /// see [`write_preimage`].
    pub fn write_preimage(&self, out: impl FnMut(&[u8])) {
        let tags = self.tags.iter().map(|t| t.iter().map(String::as_str));
        write_preimage(&self.pubkey, self.created_at, self.kind, tags, &self.content, out);
    }
}

impl UnsignedEvent {
    /// Its NIP-01 serialization, the bytes whose SHA-256 is its id, in pieces:
    /// see [`write_preimage`].
    pub fn write_preimage(&self, out: impl FnMut(&[u8])) {
        let tags = self.tags.iter().map(|t| t.iter().map(String::as_str));
        write_preimage(&self.pubkey, self.created_at, self.kind, tags, &self.content, out);
    }
}

impl CompactEvent {
    /// Its NIP-01 serialization, the bytes whose SHA-256 is its id, in pieces:
    /// see [`write_preimage`].
    pub fn write_preimage(&self, out: impl FnMut(&[u8])) {
        let tags = self.tags();
        write_preimage(&self.pubkey, self.created_at, self.kind, tags.iter().map(|t| t.iter()), self.content(), out);
    }

    pub fn content(&self) -> &str {
        let at = 4 * (self.tag_count as usize + self.field_count as usize);
        // SAFETY: the parser wrote whole UTF-8 there.
        unsafe { std::str::from_utf8_unchecked(&self.body[at..at + self.content_len as usize]) }
    }

    pub fn tags(&self) -> Tags<'_> {
        let tags = self.tag_count as usize;
        let text_at = 4 * (tags + self.field_count as usize) + self.content_len as usize;
        Tags { body: &self.body, tags, text_at }
    }

    /// The same event with its tags as owned lists.
    pub fn to_event(&self) -> Event {
        Event { id: self.id, pubkey: self.pubkey, created_at: self.created_at, kind: self.kind, tags: self.tags().to_vecs(), content: self.content().to_owned(), sig: self.sig }
    }
}

impl fmt::Debug for CompactEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = |b: &[u8]| {
            let mut s = String::new();
            encode_hex(b, &mut s);
            s
        };
        f.debug_struct("CompactEvent")
            .field("id", &hex(&self.id))
            .field("pubkey", &hex(&self.pubkey))
            .field("created_at", &self.created_at)
            .field("kind", &self.kind)
            .field("tags", &self.tags())
            .field("content", &self.content())
            .field("sig", &self.sig.map(|s| hex(&s)))
            .finish()
    }
}

/// A [`CompactEvent`]'s tags: lists of `&str` read from its body.
#[derive(Clone, Copy)]
pub struct Tags<'a> {
    body: &'a [u8],
    tags: usize,
    /// Where the tag text starts in `body`.
    text_at: usize,
}

impl<'a> Tags<'a> {
    /// How many tags.
    pub fn len(&self) -> usize {
        self.tags
    }

    pub fn is_empty(&self) -> bool {
        self.tags == 0
    }

    /// Tag `i`.
    pub fn get(&self, i: usize) -> Option<Tag<'a>> {
        if i >= self.tags {
            return None;
        }
        let last = word(self.body, i);
        let first = if i == 0 { 0 } else { word(self.body, i - 1) };
        Some(Tag { tags: *self, first, last })
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = Tag<'a>> + use<'a> {
        let tags = *self;
        (0..tags.len()).map(move |i| tags.get(i).expect("i < len"))
    }

    /// The tags as owned lists, as an [`Event`] holds them.
    pub fn to_vecs(&self) -> Vec<Vec<String>> {
        self.iter().map(|t| t.to_vec()).collect()
    }

    /// Field `k` of all of them, counted across tags.
    fn field(&self, k: usize) -> &'a str {
        let end = word(self.body, self.tags + k);
        let start = if k == 0 { 0 } else { word(self.body, self.tags + k - 1) };
        let text = &self.body[self.text_at + start..self.text_at + end];
        // SAFETY: every field the parser wrote is whole UTF-8.
        unsafe { std::str::from_utf8_unchecked(text) }
    }
}

impl fmt::Debug for Tags<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// One tag of a [`CompactEvent`]: its fields as `&str`.
#[derive(Clone, Copy)]
pub struct Tag<'a> {
    tags: Tags<'a>,
    /// Its fields, counted across tags: `first..last`.
    first: usize,
    last: usize,
}

impl<'a> Tag<'a> {
    /// How many fields.
    pub fn len(&self) -> usize {
        self.last - self.first
    }

    pub fn is_empty(&self) -> bool {
        self.first == self.last
    }

    /// Field `j`.
    pub fn get(&self, j: usize) -> Option<&'a str> {
        (j < self.len()).then(|| self.tags.field(self.first + j))
    }

    /// The first field, as in `["e", ...]`.
    pub fn name(&self) -> Option<&'a str> {
        self.get(0)
    }

    /// The fields, borrowing the event rather than this `Tag`.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &'a str> + use<'a> {
        let tag = *self;
        (tag.first..tag.last).map(move |k| tag.tags.field(k))
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

/// Parses one unsigned event, such as a NIP-59 rumor; see [`Parser::parse_unsigned`].
pub fn parse_unsigned(json: &str) -> Result<UnsignedEvent> {
    Parser::new().parse_unsigned(json)
}

/// Reusable scratch space: tags are gathered here and then moved or copied into
/// exactly the right size, and escaped strings are unescaped here and then copied
/// out at their size, so nothing the event keeps is ever reallocated.
#[derive(Default)]
pub struct Parser {
    lists: Lists,
    packed: Packed,
    spans: Spans,
    esc: Vec<u8>,
}

/// An [`Event`] in the making.
#[derive(Default)]
struct Lists {
    fields: Vec<String>,
    tags: Vec<Vec<String>>,
    out_tags: Vec<Vec<String>>,
    out_content: String,
}

/// A [`CompactEvent`] in the making: its tag text and index, and its content,
/// copied into one block at the end.
#[derive(Default)]
struct Packed {
    text: Vec<u8>,
    fields: Vec<u32>,
    tag_ends: Vec<u32>,
    /// The content's place in the input, or `None` when it had escapes and was
    /// unescaped into `content`.
    span: Option<(usize, usize)>,
    content: Vec<u8>,
}

/// An [`EventSpans`] in the making: where each string is in the input.
#[derive(Default)]
struct Spans {
    fields: Vec<Span>,
    tag_ends: Vec<u32>,
    content: Span,
}

/// A string's place in the input, quotes excluded.
#[derive(Clone, Copy, Default)]
struct Span {
    start: u32,
    end: u32,
    escaped: bool,
}

impl Span {
    fn of(self, input: &[u8]) -> RawStr<'_> {
        RawStr { bytes: &input[self.start as usize..self.end as usize], escaped: self.escaped }
    }
}

/// A JSON string as written: the bytes between its quotes, escapes untouched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawStr<'a> {
    pub bytes: &'a [u8],
    /// It contains at least one backslash escape.
    pub escaped: bool,
}

/// One event read in place by [`Parser::parse_spans`]: id, pubkey and sig
/// decoded, every string a [`RawStr`] of the input.
pub struct EventSpans<'p, 'a> {
    pub id: [u8; 32],
    pub pubkey: [u8; 32],
    pub created_at: u64,
    pub kind: u16,
    /// `None` for an unsigned event, whose sig is `""`.
    pub sig: Option<[u8; 64]>,
    pub content: RawStr<'a>,
    /// How many bytes of the input the event took, through its closing brace.
    pub end: usize,
    /// Valid JSON that readers can disagree on: a key, or the id, pubkey or sig,
    /// written with escapes, or another field's value nested more than 32 deep.
    /// A reader that must answer exactly as another one does can defer to it.
    pub unusual: bool,
    input: &'a [u8],
    fields: &'p [Span],
    tag_ends: &'p [u32],
}

impl<'p, 'a> EventSpans<'p, 'a> {
    /// Its NIP-01 serialization, the bytes whose SHA-256 is its id, in pieces
    /// (see [`write_preimage`]), from the strings as written: one with no
    /// escape passes as the slice of the input it is, copied nowhere. False
    /// when a string holds a lone surrogate escape, which no event can carry;
    /// what was written by then is not a preimage.
    pub fn write_preimage(&self, out: impl FnMut(&[u8])) -> bool {
        preimage::write_raw_preimage(&self.pubkey, self.created_at, self.kind, self.tags().map(|t| t.iter()), self.content, out)
    }

    pub fn tags(&self) -> impl ExactSizeIterator<Item = SpanTag<'p, 'a>> + use<'p, 'a> {
        let (fields, ends, input) = (self.fields, self.tag_ends, self.input);
        (0..ends.len()).map(move |i| {
            let start = if i == 0 { 0 } else { ends[i - 1] as usize };
            SpanTag { fields: &fields[start..ends[i] as usize], input }
        })
    }
}

/// One tag of an [`EventSpans`]: its fields as written.
#[derive(Clone, Copy)]
pub struct SpanTag<'p, 'a> {
    fields: &'p [Span],
    input: &'a [u8],
}

impl<'p, 'a> SpanTag<'p, 'a> {
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn get(&self, j: usize) -> Option<RawStr<'a>> {
        self.fields.get(j).map(|f| f.of(self.input))
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = RawStr<'a>> + use<'p, 'a> {
        let input = self.input;
        self.fields.iter().map(move |f| f.of(input))
    }
}

/// What a parse reads `tags` and `content` into, and builds the event from, so
/// one parse serves both event shapes.
trait Build {
    type Event;
    fn tags(&mut self, c: &mut Cur<'_>) -> Result<()>;
    fn content(&mut self, c: &mut Cur<'_>) -> Result<()>;
    /// The event, once every field has been read; `input` is the text parsed.
    fn finish(&mut self, head: Head, input: &[u8]) -> Result<Self::Event>;
}

/// The fixed-size fields.
#[derive(Default)]
struct Head {
    id: [u8; 32],
    pubkey: [u8; 32],
    created_at: u64,
    kind: u16,
    sig: Option<[u8; 64]>,
    /// Bytes read, through the closing brace.
    end: usize,
    unusual: bool,
    /// An id was read (an unsigned event may have none, or `null`).
    has_id: bool,
}

impl Build for Lists {
    type Event = Event;
    #[inline(always)]
    fn tags(&mut self, c: &mut Cur<'_>) -> Result<()> {
        self.out_tags = self.read(c)?;
        Ok(())
    }
    #[inline(always)]
    fn content(&mut self, c: &mut Cur<'_>) -> Result<()> {
        self.out_content = c.string()?;
        Ok(())
    }
    #[inline(always)]
    fn finish(&mut self, h: Head, _: &[u8]) -> Result<Event> {
        let (tags, content) = (std::mem::take(&mut self.out_tags), std::mem::take(&mut self.out_content));
        Ok(Event { id: h.id, pubkey: h.pubkey, created_at: h.created_at, kind: h.kind, tags, content, sig: h.sig })
    }
}

/// An [`UnsignedEvent`] in the making, in the [`Lists`] scratch.
struct Unsigned<'a>(&'a mut Lists);

impl Build for Unsigned<'_> {
    type Event = UnsignedEvent;
    #[inline(always)]
    fn tags(&mut self, c: &mut Cur<'_>) -> Result<()> {
        self.0.tags(c)
    }
    #[inline(always)]
    fn content(&mut self, c: &mut Cur<'_>) -> Result<()> {
        self.0.content(c)
    }
    #[inline(always)]
    fn finish(&mut self, h: Head, _: &[u8]) -> Result<UnsignedEvent> {
        let l = &mut *self.0;
        let (tags, content) = (std::mem::take(&mut l.out_tags), std::mem::take(&mut l.out_content));
        let id = h.has_id.then_some(h.id);
        Ok(UnsignedEvent { id, pubkey: h.pubkey, created_at: h.created_at, kind: h.kind, tags, content })
    }
}

impl Build for Packed {
    type Event = CompactEvent;
    #[inline(always)]
    fn tags(&mut self, c: &mut Cur<'_>) -> Result<()> {
        self.read(c)
    }
    #[inline(always)]
    fn content(&mut self, c: &mut Cur<'_>) -> Result<()> {
        self.span = c.string_span(&mut self.content)?;
        Ok(())
    }
    #[inline(always)]
    fn finish(&mut self, h: Head, input: &[u8]) -> Result<CompactEvent> {
        let content = match self.span {
            Some((start, end)) => &input[start..end],
            None => &self.content[..],
        };
        let (tags, fields) = (self.tag_ends.len(), self.fields.len());
        let too_big = |n: usize| u32::try_from(n).is_err();
        if too_big(content.len()) || too_big(self.text.len()) || too_big(tags + fields) {
            return Err(Error { msg: "event too large", pos: 0 });
        }
        let mut body = Vec::with_capacity(4 * (tags + fields) + content.len() + self.text.len());
        body.extend_from_slice(bytes_of(&self.tag_ends));
        body.extend_from_slice(bytes_of(&self.fields));
        body.extend_from_slice(content);
        body.extend_from_slice(&self.text);
        Ok(CompactEvent {
            id: h.id,
            pubkey: h.pubkey,
            created_at: h.created_at,
            kind: h.kind,
            sig: h.sig,
            content_len: content.len() as u32,
            tag_count: tags as u32,
            field_count: fields as u32,
            body: body.into_boxed_slice(),
        })
    }
}

impl Build for Spans {
    type Event = Head;
    #[inline(always)]
    fn tags(&mut self, c: &mut Cur<'_>) -> Result<()> {
        self.read(c)
    }
    #[inline(always)]
    fn content(&mut self, c: &mut Cur<'_>) -> Result<()> {
        self.content = c.raw_string()?;
        Ok(())
    }
    #[inline(always)]
    fn finish(&mut self, h: Head, _: &[u8]) -> Result<Head> {
        Ok(h)
    }
}

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
        parse_with::<_, true, true>(&mut self.lists, &mut self.esc, json)
    }

    pub fn parse_compact(&mut self, json: &str) -> Result<CompactEvent> {
        parse_with::<_, true, true>(&mut self.packed, &mut self.esc, json)
    }

    /// An unsigned event, as rust-nostr writes and reads one (a NIP-59 rumor is
    /// one): `sig` need not be there, and one that is, whatever it holds, is
    /// skipped like any other unknown key; `id` may be absent or `null`. The
    /// other fields, and refusing a duplicate key, are as for [`Self::parse`].
    pub fn parse_unsigned(&mut self, json: &str) -> Result<UnsignedEvent> {
        parse_with::<_, true, false>(&mut Unsigned(&mut self.lists), &mut self.esc, json)
    }

    /// Reads the event at the start of `json` in place: anything may follow it
    /// (inside a relay message, say), and [`EventSpans::end`] says where it
    /// stopped. Strings are checked against JSON's grammar but not decoded, so
    /// one with a lone surrogate escape, which is valid JSON, is accepted here.
    pub fn parse_spans<'p, 'a>(&'p mut self, json: &'a str) -> Result<EventSpans<'p, 'a>> {
        if u32::try_from(json.len()).is_err() {
            return Err(Error { msg: "event too large", pos: 0 });
        }
        let h = parse_with::<_, false, true>(&mut self.spans, &mut self.esc, json)?;
        let (s, input) = (&self.spans, json.as_bytes());
        Ok(EventSpans {
            id: h.id,
            pubkey: h.pubkey,
            created_at: h.created_at,
            kind: h.kind,
            sig: h.sig,
            content: s.content.of(input),
            end: h.end,
            unusual: h.unusual,
            input,
            fields: &s.fields,
            tag_ends: &s.tag_ends,
        })
    }
}

#[inline(always)]
/// `WHOLE`: the event must be all of `json`; otherwise it is the start of it,
/// and `Head::end` and `Head::unusual` are filled in. `SIGNED`: the event has a
/// `sig` and an `id`; otherwise `sig` is skipped like any unknown key and `id`
/// may be absent or `null`.
fn parse_with<B: Build, const WHOLE: bool, const SIGNED: bool>(build: &mut B, esc: &mut Vec<u8>, json: &str) -> Result<B::Event> {
    match canonical::<B, WHOLE, SIGNED>(build, esc, json) {
        Some(ev) => Ok(ev),
        None => general::<B, WHOLE, SIGNED>(build, esc, json),
    }
}

/// The layout relays and clients write: NIP-01's field order, no whitespace.
/// Each key and its punctuation is one fixed compare; anything else (another
/// order, whitespace, an extra key, an error) is left to [`general`], which
/// reads any layout and names the error.
#[inline(always)]
fn canonical<B: Build, const WHOLE: bool, const SIGNED: bool>(build: &mut B, esc: &mut Vec<u8>, json: &str) -> Option<B::Event> {
    let mut c = Cur { s: json, b: json.as_bytes(), p: 0, esc, unusual: false };
    let mut h = Head::default();
    c.lit(b"{\"id\":")?;
    c.hex(&mut h.id, "").ok()?;
    h.has_id = true;
    c.lit(b",\"pubkey\":")?;
    c.hex(&mut h.pubkey, "").ok()?;
    c.lit(b",\"created_at\":")?;
    h.created_at = c.uint().ok()?;
    c.lit(b",\"kind\":")?;
    h.kind = u16::try_from(c.uint().ok()?).ok()?;
    c.lit(b",\"tags\":")?;
    build.tags(&mut c).ok()?;
    c.lit(b",\"content\":")?;
    build.content(&mut c).ok()?;
    if SIGNED {
        c.lit(b",\"sig\":")?;
        h.sig = c.sig().ok()?;
    }
    c.lit(b"}")?;
    if WHOLE {
        if c.p != c.b.len() {
            return None;
        }
    } else {
        (h.end, h.unusual) = (c.p, c.unusual);
    }
    build.finish(h, c.b).ok()
}

fn general<B: Build, const WHOLE: bool, const SIGNED: bool>(build: &mut B, esc: &mut Vec<u8>, json: &str) -> Result<B::Event> {
    let mut c = Cur { s: json, b: json.as_bytes(), p: 0, esc, unusual: false };
    let mut h = Head::default();
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
                    if SIGNED || c.peek() != Some(b'n') {
                        c.hex(&mut h.id, "id must be 64 lowercase hex digits")?;
                        h.has_id = true;
                    } else {
                        c.literal(b"null")?;
                    }
                    ID
                }
                Key::Pubkey => {
                    c.hex(&mut h.pubkey, "pubkey must be 64 lowercase hex digits")?;
                    PUBKEY
                }
                Key::CreatedAt => {
                    h.created_at = c.uint()?;
                    CREATED_AT
                }
                Key::Kind => {
                    let p = c.p;
                    h.kind = u16::try_from(c.uint()?).map_err(|_| Error { msg: "kind out of range", pos: p })?;
                    KIND
                }
                Key::Tags => {
                    build.tags(&mut c)?;
                    TAGS
                }
                Key::Content => {
                    build.content(&mut c)?;
                    CONTENT
                }
                Key::Sig if SIGNED => {
                    h.sig = c.sig()?;
                    SIG
                }
                Key::Sig => {
                    c.skip()?;
                    0
                }
                Key::Other => {
                    c.skip()?;
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
    // An unsigned event needs neither an id nor a sig.
    let seen = if SIGNED { seen } else { seen | ID | SIG };
    if seen != ALL {
        return c.err(missing(seen));
    }
    if WHOLE {
        c.ws();
        if c.p != c.b.len() {
            return c.err("trailing characters");
        }
    } else {
        (h.end, h.unusual) = (c.p, c.unusual);
    }
    build.finish(h, c.b)
}

impl Lists {
    /// `[["e", "…"], …]`: each field is collected in `self.fields`, each tag in
    /// `self.tags`, and both are moved into exact-size lists at the end.
    fn read(&mut self, c: &mut Cur<'_>) -> Result<Vec<Vec<String>>> {
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
    /// noted in `self.fields`, each tag's end in `self.tag_ends`, ready for
    /// [`Build::finish`] to copy into the event's block.
    fn read(&mut self, c: &mut Cur<'_>) -> Result<()> {
        self.text.clear();
        self.fields.clear();
        self.tag_ends.clear();
        c.expect(b'[', "tags must be an array")?;
        c.ws();
        if c.peek() == Some(b']') {
            c.p += 1;
            return Ok(());
        }
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
        Ok(())
    }
}

impl Spans {
    /// `[["e", "…"], …]`: every field's place in `self.fields`, each tag's end
    /// in `self.tag_ends`.
    fn read(&mut self, c: &mut Cur<'_>) -> Result<()> {
        self.fields.clear();
        self.tag_ends.clear();
        c.expect(b'[', "tags must be an array")?;
        c.ws();
        if c.peek() == Some(b']') {
            c.p += 1;
            return Ok(());
        }
        loop {
            c.ws();
            c.expect(b'[', "a tag must be an array")?;
            c.ws();
            if c.peek() == Some(b']') {
                c.p += 1;
            } else {
                loop {
                    c.ws();
                    let field = c.raw_string()?;
                    self.fields.push(field);
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
        Ok(())
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
    /// See [`EventSpans::unusual`].
    unusual: bool,
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
            self.unusual = true;
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
            _ => self.escaped_hex(out, msg),
        }
    }

    /// [`Self::hex`] for a string that is not plain hex as written: JSON may spell
    /// its digits as escapes (`"\u0061…"`), so it is unescaped and checked again.
    #[cold]
    #[inline(never)]
    fn escaped_hex(&mut self, out: &mut [u8], msg: &'static str) -> Result<()> {
        let p = self.p;
        match self.string() {
            Ok(s) if s.len() == out.len() * 2 && simd::decode_hex(s.as_bytes(), out) => {
                self.unusual = true;
                Ok(())
            }
            _ => {
                self.p = p;
                self.err(msg)
            }
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

    /// A string's place in the input, checked but not unescaped: nothing is
    /// decoded, so a lone surrogate escape (valid JSON) passes.
    #[inline(always)]
    fn raw_string(&mut self) -> Result<Span> {
        self.expect(b'"', "expected a string")?;
        let start = self.p;
        let end = simd::find_special(self.b, start);
        if self.b.get(end) == Some(&b'"') {
            self.p = end + 1;
            return Ok(Span { start: start as u32, end: end as u32, escaped: false });
        }
        self.p = start - 1;
        self.skip_string()?;
        Ok(Span { start: start as u32, end: (self.p - 1) as u32, escaped: true })
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

    /// A string the caller copies later: its place in the input, or `None`
    /// when it had escapes and was unescaped into `out` (cleared first).
    #[inline(always)]
    fn string_span(&mut self, out: &mut Vec<u8>) -> Result<Option<(usize, usize)>> {
        self.expect(b'"', "expected a string")?;
        let start = self.p;
        let end = simd::find_special(self.b, start);
        if self.b.get(end) == Some(&b'"') {
            self.p = end + 1;
            return Ok(Some((start, end)));
        }
        out.clear();
        self.escaped_into(start, end, out)?;
        Ok(None)
    }

    #[cold]
    #[inline(never)]
    fn escaped_into(&mut self, start: usize, at: usize, out: &mut Vec<u8>) -> Result<()> {
        let end = unescape(self.b, start, at, out)?;
        self.p = end + 1;
        Ok(())
    }


    /// Skips one value of any kind, checking it is valid JSON. Iterative, so
    /// any depth is fine (serde_json skips an unknown field's value the same
    /// way, with no depth limit); the containers still open are kept in `open`,
    /// which allocates only when a value nests.
    fn skip(&mut self) -> Result<()> {
        let mut open: Vec<u8> = Vec::new();
        loop {
            // A value.
            self.ws();
            match self.peek() {
                Some(b'[') => {
                    self.p += 1;
                    self.ws();
                    if self.peek() == Some(b']') {
                        self.p += 1;
                    } else {
                        open.push(b'[');
                        self.unusual |= open.len() > 32;
                        continue;
                    }
                }
                Some(b'{') => {
                    self.p += 1;
                    self.ws();
                    if self.peek() == Some(b'}') {
                        self.p += 1;
                    } else {
                        open.push(b'{');
                        self.unusual |= open.len() > 32;
                        self.member_key()?;
                        continue;
                    }
                }
                Some(b'"') => self.skip_string()?,
                Some(b't') => self.literal(b"true")?,
                Some(b'f') => self.literal(b"false")?,
                Some(b'n') => self.literal(b"null")?,
                Some(b'-' | b'0'..=b'9') => self.number()?,
                _ => return self.err("expected a value"),
            }
            // After it: the next element, or containers closing.
            loop {
                let Some(&inner) = open.last() else { return Ok(()) };
                self.ws();
                match (self.next(), inner) {
                    (Some(b','), b'[') => break,
                    (Some(b','), _) => {
                        self.member_key()?;
                        break;
                    }
                    (Some(b']'), b'[') | (Some(b'}'), b'{') => {
                        open.pop();
                    }
                    (_, b'[') => return self.err_back("expected ',' or ']'"),
                    _ => return self.err_back("expected ',' or '}'"),
                }
            }
        }
    }

    /// An object member's key and its colon, in a skipped value.
    fn member_key(&mut self) -> Result<()> {
        self.ws();
        if self.peek() != Some(b'"') {
            return self.err("expected a key");
        }
        self.skip_string()?;
        self.ws();
        self.expect(b':', "expected ':'")
    }

    /// A string, checked and passed over.
    fn skip_string(&mut self) -> Result<()> {
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
            let v = unsafe { std::ptr::read_unaligned(b.as_ptr().add(i) as *const [u8; 16]) };
            unsafe { std::ptr::write_unaligned(dst.add(o) as *mut [u8; 16], v) };
            let m = simd::special_mask(v);
            // A clean block moves on by 16 without waiting for the mask's
            // position to be worked out: the next load starts at once.
            if m == 0 {
                i += 16;
                o += 16;
                continue;
            }
            let k = simd::first_of(m);
            i += k;
            o += k;
            break;
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
