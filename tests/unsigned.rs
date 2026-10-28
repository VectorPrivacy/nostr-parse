//! `parse_unsigned` against rust-nostr's own `UnsignedEvent::from_json`: wherever
//! nostr-parse accepts an event (and it converts), rust-nostr reads the same
//! event; wherever rust-nostr refuses one, nostr-parse does too. nostr-parse may
//! refuse more (uppercase hex, say), which a caller hands to rust-nostr instead.

use nostr::prelude::{EventId, Kind, PublicKey, Tag, Timestamp, UnsignedEvent as Theirs};

const PUBKEY: &str = "379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe";
const PEER: &str = "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272";

/// A JSON `\u` escape, built so this file holds none.
fn u(hex: &str) -> String {
    format!("{}u{hex}", char::from(92))
}

fn to_nostr(e: nostr_parse::UnsignedEvent) -> Option<Theirs> {
    let tags: Vec<Tag> = e.tags.into_iter().map(Tag::parse).collect::<Result<_, _>>().ok()?;
    let mut ev = Theirs::new(PublicKey::from_byte_array(e.pubkey), Timestamp::from(e.created_at), Kind::from(e.kind), tags, e.content);
    ev.id = e.id.map(EventId::from_byte_array);
    Some(ev)
}

/// Whether nostr-parse answered; panics where the two disagree.
fn agree(json: &str) -> bool {
    let theirs = Theirs::from_json(json).ok();
    let ours = nostr_parse::parse_unsigned(json).ok().and_then(to_nostr);
    match (&ours, &theirs) {
        (Some(a), Some(b)) => {
            assert_eq!(a, b, "{json}");
            assert_eq!(a.as_json(), b.as_json(), "{json}");
            true
        }
        (Some(_), None) => panic!("nostr-parse accepted what rust-nostr refuses: {json}"),
        _ => false,
    }
}

/// A DM rumor as rust-nostr writes it: id first, no sig.
fn rumor(content: &str) -> String {
    let tags = vec![
        Tag::parse(["p", PEER]).unwrap(),
        Tag::parse(["e", &"7".repeat(64), "", "reply"]).unwrap(),
        Tag::parse(["subject", "quote \" and \\ and é"]).unwrap(),
    ];
    let mut r = Theirs::new(PublicKey::from_hex(PUBKEY).unwrap(), Timestamp::from(1_761_600_000), Kind::from(14u16), tags, content);
    r.ensure_id();
    r.as_json()
}

fn id_of(json: &str) -> &str {
    let at = json.find("\"id\":\"").unwrap() + 6;
    &json[at..at + 64]
}

/// `json` with the id's first hex digit written as a `\u` escape: the same id.
fn escaped_id(json: &str) -> String {
    let first = id_of(json).as_bytes()[0];
    json.replacen(&format!("\"id\":\"{}", first as char), &format!("\"id\":\"{}", u(&format!("{first:04x}"))), 1)
}

#[test]
fn rumors_as_rust_nostr_writes_them() {
    let controls = format!("{}{}", char::from(1), char::from(0x7f));
    for content in ["", "hi", "line\nbreak \"quoted\" \\ 😀 日本", controls.as_str()] {
        let json = rumor(content);
        assert!(!json.contains("\"sig\""));
        assert!(agree(&json), "{json}");
        assert!(nostr_parse::parse_unsigned(&json).unwrap().id.is_some());
    }
}

#[test]
fn a_sig_is_ignored_whatever_it_holds() {
    let json = rumor("x");
    let body = &json[..json.len() - 1];
    let hex_sig = format!("\"{}\"", "a".repeat(128));
    for sig in ["\"\"", hex_sig.as_str(), "1", "null", "{}", "[]", "true", "\"x\"", "{\"a\":[1,{\"b\":null}]}"] {
        let once = format!("{body},\"sig\":{sig}}}");
        assert!(agree(&once), "{once}");
        let twice = format!("{body},\"sig\":{sig},\"sig\":\"\"}}");
        assert!(agree(&twice), "{twice}");
    }
}

#[test]
fn the_id_may_be_absent_or_null() {
    let json = rumor("x");
    let first = &json[..json.find(",\"pubkey\"").unwrap() + 1];
    let without = json.replacen(first, "{", 1);
    let null = json.replacen(first, "{\"id\":null,", 1);
    for (j, has) in [(json.clone(), true), (without, false), (null, false)] {
        assert!(agree(&j), "{j}");
        assert_eq!(nostr_parse::parse_unsigned(&j).unwrap().id.is_some(), has, "{j}");
    }
}

#[test]
fn other_spellings_read_alike() {
    let json = rumor("x");
    let sorted = serde_json::from_str::<serde_json::Value>(&json).unwrap().to_string();
    assert_ne!(sorted, json, "serde_json sorts the keys");
    for j in [
        sorted,
        json.replacen("\"content\"", &format!("\"{}ontent\"", u("0063")), 1),
        json.replacen("\"content\":\"x\"", &format!("\"content\":\"{}\"", u("0078")), 1),
        escaped_id(&json),
        format!(" {} ", json.replacen(",\"tags\"", " ,\n\t\"tags\" : ", 1).replacen("\"tags\" : :", "\"tags\" :", 1)),
        json.replacen(",\"tags\"", ",\"extra\":{\"deep\":[[[1]]]},\"tags\"", 1),
    ] {
        assert!(agree(&j), "{j}");
    }
}

#[test]
fn what_rust_nostr_refuses_is_refused() {
    let json = rumor("x");
    let body = &json[..json.len() - 1];
    for j in [
        format!("{body},\"id\":null}}"),
        format!("{body},\"content\":\"y\"}}"),
        json.replacen("\"kind\":14", "\"kind\":70000", 1),
        json.replacen("\"kind\":14", "\"kind\":-1", 1),
        json.replacen("\"created_at\":1761600000", "\"created_at\":1.5", 1),
        json.replacen("\"tags\":[", "\"tags\":[[],", 1),
        json.replacen("\"tags\":[", "\"tags\":[[1],", 1),
        json.replacen(",\"content\":\"x\"", "", 1),
        json.replacen(&format!("\"pubkey\":\"{PUBKEY}\","), "", 1),
        format!("{json} x"),
        json.replacen("\"content\":\"x\"", &format!("\"content\":\"{}\"", u("d83d")), 1),
        json.replacen(id_of(&json), "", 1),
    ] {
        assert!(Theirs::from_json(&j).is_err(), "rust-nostr reads it: {j}");
        assert!(!agree(&j), "{j}");
    }
}

#[test]
fn uppercase_hex_is_left_to_rust_nostr() {
    let json = rumor("x");
    let upper = json.replacen(id_of(&json), &id_of(&json).to_uppercase(), 1);
    assert!(nostr_parse::parse_unsigned(&upper).is_err());
    assert!(!agree(&upper));
}

#[test]
fn the_signed_readers_still_need_a_sig() {
    let json = rumor("x");
    assert!(nostr_parse::parse(&json).is_err());
    assert!(nostr_parse::parse_compact(&json).is_err());
    assert!(nostr_parse::Parser::new().parse_spans(&json).is_err());
    let signed = format!("{},\"sig\":\"{}\"}}", &json[..json.len() - 1], "b".repeat(128));
    assert!(nostr_parse::parse(&signed).is_ok());
}
