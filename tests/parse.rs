use nostr_parse::{CompactEvent, Event, Parser, encode_hex, parse, parse_compact};

const ID: &str = "4376c65d2f232afbe9b882a35baa4f6fe8667c4e684749af565f981833ed6a65";
const PK: &str = "6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93";
const SIG: &str = "908a15e46fb4d8675bab026fc230a0e3542bfade63da02d542fb78b2a8513fcd0092619a2c8c1221e581946e0191f2af505dfdf8657a414dbca329186f009262";

fn event(tags: &str, content: &str, sig: &str) -> String {
    format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":1673347337,"kind":1,"tags":{tags},"content":{content},"sig":"{sig}"}}"#)
}

/// A compact event as the list-of-strings one, to compare with it.
fn lists(e: CompactEvent) -> Event {
    e.to_event()
}

/// The event serde_json reads from the same text, field by field.
fn reference(json: &str) -> Event {
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    let hex = |s: &str| {
        let mut out = vec![0u8; s.len() / 2];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    };
    let sig = v["sig"].as_str().unwrap();
    Event {
        id: hex(v["id"].as_str().unwrap()).try_into().unwrap(),
        pubkey: hex(v["pubkey"].as_str().unwrap()).try_into().unwrap(),
        created_at: v["created_at"].as_u64().unwrap(),
        kind: v["kind"].as_u64().unwrap() as u16,
        tags: v["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_owned()).collect())
            .collect(),
        content: v["content"].as_str().unwrap().to_owned(),
        sig: (!sig.is_empty()).then(|| hex(sig).try_into().unwrap()),
    }
}

#[track_caller]
fn same(json: &str) {
    let want = reference(json);
    assert_eq!(parse(json).unwrap(), want, "{json}");
    assert_eq!(lists(parse_compact(json).unwrap()), want, "compact: {json}");
}

#[test]
fn reads_what_serde_json_reads() {
    same(&event("[]", r#""hello""#, SIG));
    same(&event(r#"[["e","abc"],["p","def","wss://relay"],[],["t"]]"#, r#""""#, SIG));
    same(&event("[]", r#""line\nbreak \"quoted\" back\\slash \/ tab\t""#, SIG));
    same(&event("[]", r#""emoji 😀 and é and  ""#, SIG));
    same(&event(r#"[["subject","café 🎉"]]"#, r#""ünïcödé straight in 🎉""#, SIG));
    same(&event("[]", r#""a long string that is well over sixteen bytes, so it takes the block path, then \n an escape right at the end\"""#, SIG));
    same(&event("[]", r#""""#, ""));
    // Whitespace anywhere JSON allows it, and keys in another order.
    same(&format!(
        " {{ \"sig\" : \"{SIG}\" ,\n\t\"content\":\"x\", \"tags\" : [ [ \"a\" , \"b\" ] , [ ] ] , \"kind\":0,\"created_at\" : 0 , \"pubkey\":\"{PK}\",\"id\":\"{ID}\" }} "
    ));
    // Unknown keys of every kind are skipped.
    same(&format!(
        r#"{{"id":"{ID}","extra":{{"a":[1,-2.5e+3,true,false,null,"s\"t"],"b":{{}}}},"pubkey":"{PK}","created_at":1,"kind":7,"tags":[],"content":"+","sig":"{SIG}","x":[]}}"#
    ));
    // The largest timestamps: 19 digits, and u64::MAX's 20.
    for t in ["9999999999999999999", "18446744073709551615"] {
        same(&format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":{t},"kind":65535,"tags":[],"content":"","sig":""}}"#));
    }
    // An escaped key still names its field.
    same(&format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":1,"kind":7,"tags":[],"content":"+","sig":"{SIG}"}}"#));
}

#[test]
fn refuses_what_nip01_refuses() {
    let bad = [
        event("[]", r#""x""#, &SIG.to_uppercase()),
        event("[]", r#""x""#, &SIG[..126]),
        event("[[1]]", r#""x""#, SIG),
        event(r#"["e"]"#, r#""x""#, SIG),
        event("[]", r#""lone \ud83d surrogate""#, SIG),
        event("[]", r#""lone \ude00 low""#, SIG),
        event("[]", r#""bad \x escape""#, SIG),
        event("[]", "\"raw\ncontrol\"", SIG),
        event("[]", r#""unterminated"#, SIG),
        event("[]", "null", SIG),
        format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":1,"kind":7,"tags":[],"content":"x"}}"#),
        format!(r#"{{"id":"{ID}","id":"{ID}","pubkey":"{PK}","created_at":1,"kind":7,"tags":[],"content":"x","sig":""}}"#),
        format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":01,"kind":7,"tags":[],"content":"x","sig":""}}"#),
        format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":1.5,"kind":7,"tags":[],"content":"x","sig":""}}"#),
        format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":-1,"kind":7,"tags":[],"content":"x","sig":""}}"#),
        format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":1,"kind":65536,"tags":[],"content":"x","sig":""}}"#),
        format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":18446744073709551616,"kind":7,"tags":[],"content":"x","sig":""}}"#),
        format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":1,"kind":7,"tags":[],"content":"x","sig":"","z":tru}}"#),
        format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":1,"kind":7,"tags":[],"content":"x","sig":""}} x"#),
        format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":1,"kind":7,"tags":[],"content":"x","sig":"",}}"#),
        event("[],", r#""x""#, SIG),
        String::from("[]"),
        String::new(),
    ];
    for json in &bad {
        assert!(parse(json).is_err(), "accepted: {json}");
        assert_eq!(parse_compact(json).err(), parse(json).err(), "compact, same error: {json}");
    }
}

#[test]
fn hex_round_trips_every_digit() {
    let mut s = String::new();
    let bytes: Vec<u8> = (0..64).map(|i| (i * 37 + 11) as u8).collect();
    encode_hex(&bytes, &mut s);
    let ev = parse(&event("[]", r#""""#, &s)).unwrap();
    assert_eq!(ev.sig.unwrap().to_vec(), bytes);
    // Every digit and letter in both nibble positions.
    let all: String = "0123456789abcdef".chars().cycle().take(128).collect();
    let ev = parse(&event("[]", r#""""#, &all)).unwrap();
    let mut back = String::new();
    encode_hex(&ev.sig.unwrap(), &mut back);
    assert_eq!(back, all);
}

/// Escapes at every offset across the 16-byte blocks, in tag fields and content
/// (far from the end of the input) and in content before an empty sig (within 16
/// bytes of the end, where only the byte-at-a-time tail runs), against serde_json.
#[test]
fn escapes_at_every_offset_match_serde_json() {
    let pieces = [r"\n", r#"\""#, r"\\", r"\/", r"é", r"😀", r" ", "é", "🎉", r"\t\r\b\f"];
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut rand = |n: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % n as u64) as usize
    };
    for len in 0..48 {
        for piece in pieces {
            for at in 0..=len {
                let mut s = "x".repeat(at);
                s.push_str(piece);
                s.push_str(&"y".repeat(len - at));
                // Sometimes a second escape somewhere after the first.
                if rand(3) == 0 {
                    s.push_str(pieces[rand(pieces.len())]);
                    s.push_str(&"z".repeat(rand(20)));
                }
                let q = format!("\"{s}\"");
                same(&event(&format!("[[{q},{q}],[\"p\",{q}]]"), &q, SIG));
                same(&event("[]", &q, ""));
            }
        }
    }
}

/// A compact event's tags read back field by field: empty tags, empty fields,
/// escaped fields and multi-byte text all where they belong.
#[test]
fn compact_tags_read_back() {
    let json = event(r#"[["e","abc"],[],["",""],["t","caf\u00e9 \ud83c\udf89"],["p"]]"#, r#""x""#, SIG);
    let ev = parse_compact(&json).unwrap();
    let tags = ev.tags();
    assert_eq!(tags.len(), 5);
    let all: Vec<Vec<&str>> = tags.iter().map(|t| t.iter().collect()).collect();
    assert_eq!(all, vec![vec!["e", "abc"], vec![], vec!["", ""], vec!["t", "café 🎉"], vec!["p"]]);
    let t = tags.get(3).unwrap();
    assert_eq!((t.name(), t.get(1), t.get(2), t.len()), (Some("t"), Some("café 🎉"), None, 2));
    assert!(tags.get(1).unwrap().is_empty() && tags.get(1).unwrap().name().is_none());
    assert!(tags.get(5).is_none());
    assert_eq!(format!("{tags:?}"), r#"[["e", "abc"], [], ["", ""], ["t", "café 🎉"], ["p"]]"#);
    let bare = parse_compact(&event("[]", r#""x""#, SIG)).unwrap();
    assert!(bare.tags().is_empty() && bare.tags().iter().next().is_none() && bare.content() == "x");
    let empty = parse_compact(&event("[]", r#""""#, SIG)).unwrap();
    assert!(empty.tags().is_empty() && empty.content().is_empty());
}

/// One `Parser` across events: nothing of one event's tags or content leaks
/// into the next, and an escaped key read after escaped content (only the
/// general path does that) leaves the content alone.
#[test]
fn a_parser_reused_keeps_events_apart() {
    let mut p = Parser::new();
    let with = event(r#"[["e","abc"],["p","def"]]"#, r#""line\none""#, SIG);
    let without = event("[]", r#""plain""#, SIG);
    let content_then_key = format!(r#"{{"id":"{ID}","pubkey":"{PK}","created_at":1,"kind":1,"content":"a\"b","tags":[["t","x"]],"sig":"{SIG}"}}"#);
    for json in [&with, &without, &content_then_key, &with, &without] {
        assert_eq!(p.parse_compact(json).unwrap().to_event(), reference(json), "{json}");
        assert_eq!(p.parse(json).unwrap(), reference(json), "{json}");
    }
    // A failed parse (an error after the tags) leaves nothing behind either.
    assert!(p.parse_compact(&event(r#"[["e","stale"]]"#, "1", SIG)).is_err());
    assert_eq!(p.parse_compact(&without).unwrap().to_event(), reference(&without));
}
