//! `write_preimage` against what rust-nostr hashes for an event id: the same
//! bytes as `serde_json::to_vec` of `(0, pubkey, created_at, kind, tags, content)`,
//! from every shape, and ids built from them that rust-nostr's own
//! `Event::verify_id` accepts.

use nostr_parse::{Parser, RawStr};
use sha2::{Digest, Sha256};

/// A JSON `\u` escape, built so this file holds none.
fn u(hex: &str) -> String {
    format!("{}u{hex}", char::from(92))
}

fn bs() -> char {
    char::from(92)
}

const PUBKEY: &str = "379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe";

fn collect(write: impl FnOnce(&mut dyn FnMut(&[u8]))) -> Vec<u8> {
    let mut bytes = Vec::new();
    write(&mut |b| bytes.extend_from_slice(b));
    bytes
}

/// An event whose strings are written exactly as given (escapes and all), with
/// the id its preimage hashes to, and that preimage.
fn event(tags_json: &str, content_json: &str) -> (String, Vec<u8>) {
    let partial = format!(
        "{{\"id\":\"{}\",\"pubkey\":\"{PUBKEY}\",\"created_at\":1761600000,\"kind\":1,\"tags\":{tags_json},\"content\":\"{content_json}\",\"sig\":\"{}\"}}",
        "0".repeat(64),
        "a".repeat(128)
    );
    let ev = nostr_parse::parse(&partial).expect("a valid event");
    let pre = collect(|out| ev.write_preimage(out));
    let id: String = Sha256::digest(&pre).iter().map(|b| format!("{b:02x}")).collect();
    (partial.replacen(&"0".repeat(64), &id, 1), pre)
}

fn serde_preimage(json: &str) -> Vec<u8> {
    let ev = nostr_parse::parse(json).unwrap();
    serde_json::to_vec(&(0u8, PUBKEY, ev.created_at, ev.kind, &ev.tags, &ev.content)).unwrap()
}

/// Every shape writes the same bytes as serde_json, and rust-nostr agrees on the id.
fn agree(tags_json: &str, content_json: &str) {
    let (json, pre) = event(tags_json, content_json);
    assert_eq!(pre, serde_preimage(&json), "{json}");
    let mut p = Parser::new();
    let compact = p.parse_compact(&json).unwrap();
    assert_eq!(collect(|out| compact.write_preimage(out)), pre, "CompactEvent: {json}");
    let unsigned = p.parse_unsigned(&json).unwrap();
    assert_eq!(collect(|out| unsigned.write_preimage(out)), pre, "UnsignedEvent: {json}");
    let sp = p.parse_spans(&json).unwrap();
    let mut raw = Vec::new();
    assert!(sp.write_preimage(|b| raw.extend_from_slice(b)), "{json}");
    assert_eq!(raw, pre, "EventSpans: {json}");
    let theirs = nostr::prelude::Event::from_json(&json).expect("rust-nostr reads it");
    assert!(theirs.verify_id(), "rust-nostr computes another id for {json}");
}

#[test]
fn plain_events() {
    agree("[]", "");
    agree("[]", "hello world");
    agree(&format!("[[\"p\",\"{PUBKEY}\"],[\"e\",\"{}\",\"\",\"reply\"]]", "7".repeat(64)), "gm");
    agree("[[\"t\",\"nostr\"],[\"t\",\"rust\"]]", "a long note ".repeat(40).as_str());
}

#[test]
fn every_control_character_and_the_ones_left_alone() {
    // Each control character written the way serde_json writes it, plus DEL,
    // slash and non-ASCII, which it leaves as they are.
    let mut content = String::new();
    for c in 0u32..0x20 {
        content.push_str(&match c {
            0x08 => format!("{}b", bs()),
            0x09 => format!("{}t", bs()),
            0x0A => format!("{}n", bs()),
            0x0C => format!("{}f", bs()),
            0x0D => format!("{}r", bs()),
            _ => u(&format!("{c:04x}")),
        });
    }
    let (b, del) = (bs(), char::from(0x7f));
    content.push_str(&format!("{b}\" {b}{b} / {del} é 日本 😀"));
    agree(&format!("[[\"x\",\"{content}\"]]"), &content);
}

#[test]
fn other_spellings_of_the_same_strings() {
    // Escapes a writer may choose that serde_json would not: each must hash as
    // the character it stands for.
    let spellings = [
        u("00e9"),                         // é
        u("00E9"),                         // é, uppercase hex
        format!("{}/", bs()),              // /
        u("002f"),                         // /
        u("0041"),                         // A
        u("0022"),                         // "
        u("005C"),                         // backslash
        u("001F"),                         // a control character, uppercase hex
        u("007f"),                         // DEL
        format!("{}{}", u("d83d"), u("de00")), // 😀 as a surrogate pair
        u("2028"),                         // line separator
    ];
    for s in &spellings {
        agree(&format!("[[\"t\",\"{s}\"]]"), &format!("before {s} after"));
    }
}

#[test]
fn a_lone_surrogate_has_no_preimage() {
    let json = format!(
        "{{\"id\":\"{}\",\"pubkey\":\"{PUBKEY}\",\"created_at\":1,\"kind\":1,\"tags\":[],\"content\":\"{}\",\"sig\":\"{}\"}}",
        "0".repeat(64),
        u("d83d"),
        "a".repeat(128)
    );
    let mut p = Parser::new();
    assert!(p.parse(&json).is_err(), "decoding refuses it");
    let sp = p.parse_spans(&json).expect("valid JSON: spans read it");
    assert!(!sp.write_preimage(|_| {}));
}

#[test]
fn the_free_function_takes_fields_from_anywhere() {
    // An empty tag too, which rust-nostr refuses to read but serde_json writes as `[]`.
    let tags = vec![vec!["p".to_string(), PUBKEY.to_string()], vec![]];
    let bytes = collect(|out| nostr_parse::write_preimage(&[0xab; 32], 7, 30023, tags.iter().map(|t| t.iter().map(String::as_str)), "x\ny", out));
    let want = serde_json::to_vec(&(0u8, "ab".repeat(32), 7u64, 30023u16, &tags, "x\ny")).unwrap();
    assert_eq!(bytes, want);
    // An empty input is a raw string that needs no copy.
    assert!(RawStr { bytes: b"", escaped: false }.bytes.is_empty());
}
