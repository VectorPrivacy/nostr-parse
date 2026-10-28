//! `Parser::parse_spans`: an event read in place, its strings as written.

use nostr_parse::{Parser, RawStr};

const ID: &str = "70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5";
const PUBKEY: &str = "379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe";
const SIG: &str = "273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502";

fn event(tags: &str, content: &str) -> String {
    format!(r#"{{"id":"{ID}","pubkey":"{PUBKEY}","created_at":1612809991,"kind":1,"tags":{tags},"content":{content},"sig":"{SIG}"}}"#)
}

fn raw(s: &str, escaped: bool) -> RawStr<'_> {
    RawStr { bytes: s.as_bytes(), escaped }
}

#[test]
fn strings_come_back_as_written() {
    let json = event(r#"[["e","abc"],["p","d\"ef","wss://r"],[]]"#, r#""line\nbreak é""#);
    let mut p = Parser::new();
    let ev = p.parse_spans(&json).unwrap();
    assert_eq!(ev.content, raw(r"line\nbreak é", true));
    let tags: Vec<Vec<RawStr<'_>>> = ev.tags().map(|t| t.iter().collect()).collect();
    assert_eq!(tags, vec![vec![raw("e", false), raw("abc", false)], vec![raw("p", false), raw(r#"d\"ef"#, true), raw("wss://r", false)], vec![]]);
    assert_eq!((ev.created_at, ev.kind, ev.end, ev.unusual), (1612809991, 1, json.len(), false));
    assert_eq!(ev.tags().nth(1).unwrap().get(2), Some(raw("wss://r", false)));
    assert!(ev.sig.is_some());
}

#[test]
fn the_event_may_be_followed_by_anything() {
    for (json, rest) in [
        (event("[]", r#""x""#), r#"]"#),
        (format!(" \n{}", event("[]", r#""x""#)), " , \"tail\"]"),
        (event("[]", r#""x""#).replace(":", " : "), "}{"),
    ] {
        let input = format!("{json}{rest}");
        let mut p = Parser::new();
        let ev = p.parse_spans(&input).unwrap();
        assert_eq!(ev.end, json.len(), "{input}");
        // Read as a whole document, the same text is refused.
        assert!(p.parse(&input).is_err());
    }
}

#[test]
fn a_lone_surrogate_passes_because_nothing_is_decoded() {
    let json = event("[]", r#""half \ud83d a heart""#);
    let mut p = Parser::new();
    assert_eq!(p.parse_spans(&json).unwrap().content, raw(r"half \ud83d a heart", true));
    assert!(p.parse(&json).is_err());
}

#[test]
fn unusual_spellings_are_flagged() {
    let mut p = Parser::new();
    let deep = |n: usize| format!(r#","extra":{}{}"#, "[".repeat(n), "]".repeat(n));
    let plain = event("[]", r#""x""#);
    for (json, unusual) in [
        (plain.clone(), false),
        (plain.replacen(r#""id""#, r#""\u0069d""#, 1), true),
        (plain.replacen(&format!(r#""{}"#, &ID[..2]), r#""\u0037\u0030"#, 1), true),
        (plain.replacen(&format!(r#""{}"#, &SIG[..1]), r#""\u0032"#, 1), true),
        (plain.replacen(r#","sig""#, &format!(r#"{},"sig""#, deep(32)), 1), false),
        (plain.replacen(r#","sig""#, &format!(r#"{},"sig""#, deep(40)), 1), true),
        (plain.replacen(r#","sig""#, r#","\u0078tra":1,"sig""#, 1), true),
    ] {
        let ev = p.parse_spans(&json).unwrap_or_else(|e| panic!("{json}: {e}"));
        assert_eq!(ev.unusual, unusual, "{json}");
        assert_eq!(ev.end, json.len());
    }
}

#[test]
fn what_parse_refuses_for_its_fields_spans_refuses_too() {
    let mut p = Parser::new();
    for json in [
        event(r#"[["e",1]]"#, r#""x""#),
        event("[]", r#""bad \x escape""#),
        event("[]", "\"raw\u{1}control\""),
        event("[]", r#""x""#).replace(r#""kind":1"#, r#""kind":65536"#),
        event("[]", r#""x""#).replace(ID, &ID.to_uppercase()),
        event("[]", r#""x""#).replacen(r#""content":"x","#, "", 1),
        event("[]", r#""x""#).replacen(r#""content""#, r#""content":"a","content""#, 1),
    ] {
        assert!(p.parse_spans(&json).is_err(), "{json}");
    }
}
