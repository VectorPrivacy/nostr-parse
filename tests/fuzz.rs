//! Differential fuzzing against serde_json: random events, mutations of them,
//! and arbitrary JSON. Both shapes of nostr-parse, and a serde_json reader of
//! the same NIP-01 rules, must agree on accepting or refusing each input and on
//! the event read. A disagreement is shrunk to a small input and reported.
//!
//! A short run comes with `cargo test`; a long one:
//!
//!   FUZZ_SECS=600 cargo test --release --test fuzz -- --ignored --nocapture

use nostr_parse::{Event, Parser};
use serde::de::{self, Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
use std::fmt;
use std::time::{Duration, Instant};

// ── the reference ───────────────────────────────────────────────────────────

/// One known field's value, as serde_json reads it.
enum Field {
    Str(String),
    Int(u64),
    Tags(Vec<Vec<String>>),
}

/// An object read key by key, so a repeated key is seen (serde_json's own
/// `Value` keeps only the last).
struct Fields(Vec<(String, Field)>);

impl<'de> Deserialize<'de> for Fields {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Fields;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an event object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Fields, A::Error> {
                let mut out: Vec<(String, Field)> = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    let field = match key.as_str() {
                        "id" | "pubkey" | "sig" | "content" => Field::Str(map.next_value()?),
                        "created_at" | "kind" => Field::Int(map.next_value()?),
                        "tags" => Field::Tags(map.next_value()?),
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    };
                    if out.iter().any(|(k, _)| *k == key) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    out.push((key, field));
                }
                Ok(Fields(out))
            }
        }
        d.deserialize_map(V)
    }
}

fn hex_bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// The event NIP-01 says the text is, read with serde_json; `None` to refuse.
fn reference(json: &str) -> Option<Event> {
    let Fields(fields) = serde_json::from_str(json).ok()?;
    let get = |k: &str| fields.iter().find(|(key, _)| key == k).map(|(_, v)| v);
    let text = |k: &str| match get(k)? {
        Field::Str(s) => Some(s.clone()),
        _ => None,
    };
    let int = |k: &str| match get(k)? {
        Field::Int(n) => Some(*n),
        _ => None,
    };
    let sig = text("sig")?;
    Some(Event {
        id: hex_bytes(&text("id")?)?,
        pubkey: hex_bytes(&text("pubkey")?)?,
        created_at: int("created_at")?,
        kind: u16::try_from(int("kind")?).ok()?,
        tags: match get("tags")? {
            Field::Tags(t) => t.clone(),
            _ => return None,
        },
        content: text("content")?,
        sig: if sig.is_empty() { None } else { Some(hex_bytes(&sig)?) },
    })
}

/// What went wrong with one input, if anything.
fn disagreement(p: &mut Parser, json: &str) -> Option<String> {
    let want = reference(json);
    let plain = p.parse(json);
    let compact = p.parse_compact(json).map(|e| e.to_event());
    let fresh = nostr_parse::parse(json);
    let show = |r: &Result<Event, nostr_parse::Error>| match r {
        Ok(_) => "accepted".to_string(),
        Err(e) => format!("refused ({e})"),
    };
    match &want {
        Some(ev) => {
            for (name, got) in [("Event", &plain), ("CompactEvent", &compact), ("Event, fresh parser", &fresh)] {
                match got {
                    Ok(g) if g == ev => {}
                    Ok(g) => return Some(format!("{name} read it differently: {g:?} vs serde_json's {ev:?}")),
                    Err(e) => return Some(format!("{name} refused what serde_json accepts: {e}")),
                }
            }
        }
        None => {
            if plain.is_ok() || compact.is_ok() || fresh.is_ok() {
                return Some(format!("serde_json refuses; Event {}, CompactEvent {}, fresh {}", show(&plain), show(&compact), show(&fresh)));
            }
        }
    }
    None
}

// ── inputs ──────────────────────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

fn hex(r: &mut Rng, n: usize) -> String {
    (0..n).map(|_| *r.pick(b"0123456789abcdef") as char).collect()
}

/// A JSON string literal for random text, with every way JSON can spell it:
/// plain, `\uXXXX` in either case, surrogate pairs, `\/`; and now and then
/// something invalid (a lone surrogate, a bad escape, a raw control byte).
fn string(r: &mut Rng, text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        let esc = r.chance(6);
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' if !esc => out.push_str("\\n"),
            '\t' if !esc => out.push_str("\\t"),
            '/' if r.chance(3) => out.push_str("\\/"),
            c if (c as u32) < 0x20 || esc => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    out.push_str(&if r.chance(2) { format!("\\u{:04x}", u) } else { format!("\\u{:04X}", u) });
                }
            }
            c => out.push(c),
        }
    }
    if r.chance(60) {
        out.push_str(r.pick::<&str>(&["\\ud83d", "\\ude00", "\\x41", "\\u12", "\u{1}", "\\", "\\uDBFFx"]));
    }
    out.push('"');
    out
}

fn text(r: &mut Rng) -> String {
    let pool: &[&str] = &["a", "Z", "0", " ", "\"", "\\", "/", "\n", "\t", "é", "🎉", "€", "\u{7f}", "\u{1}", "{", "}", "[", "]", ",", ":", "u", "x", "wss://relay.example.com", "\u{2028}", "\u{feff}"];
    let n = match r.below(10) {
        0 => 0,
        1..=6 => r.below(12),
        7 | 8 => r.below(80),
        _ => r.below(600),
    };
    (0..n).map(|_| *r.pick(pool)).collect()
}

/// Whitespace JSON allows, now and then.
fn ws(r: &mut Rng) -> &'static str {
    if r.chance(8) { r.pick::<&str>(&[" ", "\n", "\t", "\r\n ", "  "]) } else { "" }
}

/// Any JSON value, up to `depth` levels deep.
fn value(r: &mut Rng, depth: usize) -> String {
    match if depth == 0 { r.below(4) } else { r.below(7) } {
        0 => {
            let t = text(r);
            string(r, &t)
        }
        1 => r.pick(&["0", "-0", "1", "-1", "12.5", "1e3", "1E-3", "-0.0e+00", "1e999", "18446744073709551616", "123456789012345678901234567890"]).to_string(),
        2 => r.pick(&["true", "false", "null"]).to_string(),
        3 => r.pick(&["\"\"", "[]", "{}"]).to_string(),
        4 | 5 => {
            let n = r.below(4);
            let items: Vec<String> = (0..n).map(|_| value(r, depth - 1)).collect();
            format!("[{}{}]", ws(r), items.join(","))
        }
        _ => {
            let n = r.below(4);
            let items: Vec<String> = (0..n).map(|i| format!("{}:{}{}", string(r, &format!("k{i}")), ws(r), value(r, depth - 1))).collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

/// `n` arrays deep, around a value.
fn nested(r: &mut Rng, n: usize) -> String {
    let (open, close) = if r.chance(2) { ("[", "]") } else { ("{\"k\":", "}") };
    format!("{}0{}", open.repeat(n), close.repeat(n))
}

/// A random event: usually valid, often in another order or spacing, with
/// extra keys, escaped keys and odd values now and then.
fn event(r: &mut Rng) -> String {
    let id = if r.chance(30) { hex(r, 63) } else if r.chance(30) { hex(r, 64).to_uppercase() } else { hex(r, 64) };
    let pubkey = hex(r, 64);
    let sig = match r.below(12) {
        0 => String::new(),
        1 => hex(r, 127),
        _ => hex(r, 128),
    };
    let created_at = match r.below(14) {
        0 => "0".to_string(),
        1 => "18446744073709551615".to_string(),
        2 => "18446744073709551616".to_string(),
        3 => r.pick(&["1.0", "-1", "01", "1e3", "\"5\"", "null"]).to_string(),
        _ => (1_600_000_000 + r.below(200_000_000)).to_string(),
    };
    let kind = match r.below(14) {
        0 => "65535".to_string(),
        1 => "65536".to_string(),
        2 => r.pick(&["-0", "1.5", "07"]).to_string(),
        _ => r.below(40_000).to_string(),
    };
    let ntags = match r.below(10) {
        0 => 0,
        1..=7 => r.below(6),
        8 => r.below(30),
        _ => r.below(120),
    };
    let tags: Vec<String> = (0..ntags)
        .map(|_| {
            let n = r.below(5);
            let fields: Vec<String> = (0..n)
                .map(|_| {
                    let t = text(r);
                    string(r, &t)
                })
                .collect();
            if r.chance(80) { r.pick(&["[1]", "[null]", "\"e\"", "[[]]"]).to_string() } else { format!("[{}{}{}]", ws(r), fields.join(&format!("{},{}", ws(r), ws(r))), ws(r)) }
        })
        .collect();
    let content = text(r);
    let mut keys: Vec<(String, String)> = vec![
        ("id".into(), string(r, &id)),
        ("pubkey".into(), string(r, &pubkey)),
        ("created_at".into(), created_at),
        ("kind".into(), kind),
        ("tags".into(), format!("[{}]", tags.join(","))),
        ("content".into(), string(r, &content)),
        ("sig".into(), string(r, &sig)),
    ];
    if r.chance(4) {
        for i in (1..keys.len()).rev() {
            let j = r.below(i + 1);
            keys.swap(i, j);
        }
    }
    if r.chance(10) {
        let at = r.below(keys.len() + 1);
        let v = if r.chance(5) {
            let depth = 50 + r.below(160);
            nested(r, depth)
        } else {
            value(r, 4)
        };
        keys.insert(at, (r.pick(&["extra", "", "ids", "Id", "tag", "sig2"]).to_string(), v));
    }
    if r.chance(40) {
        let dup = keys[r.below(keys.len())].clone();
        keys.push(dup);
    }
    if r.chance(40) {
        keys.remove(r.below(keys.len()));
    }
    let body: Vec<String> = keys
        .iter()
        .map(|(k, v)| {
            let key = if r.chance(25) { string(r, k) } else { format!("\"{k}\"") };
            format!("{}{key}{}:{}{v}", ws(r), ws(r), ws(r))
        })
        .collect();
    format!("{}{{{}{}}}{}", ws(r), body.join(","), ws(r), ws(r))
}

/// A random edit of `s`: characters deleted, repeated, swapped or inserted.
fn mutate(r: &mut Rng, s: &str) -> String {
    let mut c: Vec<char> = s.chars().collect();
    for _ in 0..1 + r.below(3) {
        let at = r.below(c.len() + 1);
        match r.below(6) {
            0 if !c.is_empty() => {
                let n = 1 + r.below(8);
                c.drain(at.min(c.len() - 1)..(at + n).min(c.len()));
            }
            1 if at < c.len() => {
                let end = (at + 1 + r.below(20)).min(c.len());
                let piece: Vec<char> = c[at..end].to_vec();
                c.splice(at..at, piece);
            }
            2 if at < c.len() => c[at] = *r.pick(&['"', '\\', '{', '}', '[', ']', ',', ':', ' ', 'u', '0', 'e', '-', '.', '\u{1}', 'é']),
            3 => c.truncate(at),
            _ => c.insert(at, *r.pick(&['"', '\\', '{', '}', '[', ']', ',', ':', ' ', 'u', '0', 'e', '-', '.', '\n', 'x'])),
        }
    }
    c.into_iter().collect()
}

fn input(r: &mut Rng) -> String {
    match r.below(10) {
        0 => value(r, 5),
        1..=4 => {
            let e = event(r);
            mutate(r, &e)
        }
        _ => event(r),
    }
}

/// The smallest input, by deleting characters, that still disagrees.
fn shrink(p: &mut Parser, mut s: String) -> String {
    let mut chunk = s.chars().count() / 2;
    while chunk > 0 {
        let mut i = 0;
        let mut progressed = false;
        while i < s.chars().count() {
            let cand: String = s.chars().take(i).chain(s.chars().skip(i + chunk)).collect();
            if disagreement(p, &cand).is_some() {
                s = cand;
                progressed = true;
            } else {
                i += chunk;
            }
        }
        if !progressed {
            chunk /= 2;
        }
    }
    s
}

fn run(seed: u64, budget: Duration) -> (u64, u64) {
    let mut r = Rng(seed | 1);
    let mut p = Parser::new();
    let (mut n, mut accepted) = (0u64, 0u64);
    let end = Instant::now() + budget;
    while Instant::now() < end {
        for _ in 0..256 {
            let json = input(&mut r);
            if let Some(why) = disagreement(&mut p, &json) {
                let small = shrink(&mut p, json.clone());
                panic!("seed {seed}, input {n}: {why}\nshrunk to {small:?}\n{}\nfull input: {json:?}", disagreement(&mut p, &small).unwrap());
            }
            accepted += u64::from(reference(&json).is_some());
            n += 1;
        }
    }
    (n, accepted)
}

#[test]
fn agrees_with_serde_json_briefly() {
    let (n, ok) = run(0x5eed, Duration::from_secs(3));
    assert!(n > 1000 && ok > 0 && ok < n, "{n} inputs, {ok} accepted");
}

#[test]
#[ignore]
fn agrees_with_serde_json_for_long() {
    let secs: u64 = std::env::var("FUZZ_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(60);
    let threads: u64 = std::env::var("FUZZ_THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(4);
    let start = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64 ^ 0x9e37_79b9_7f4a_7c15;
    println!("seeds from {start}");
    let handles: Vec<_> = (0..threads).map(|t| std::thread::spawn(move || run(start.wrapping_add(t.wrapping_mul(0x632b_e59b_d9b4_e019)), Duration::from_secs(secs)))).collect();
    let (mut n, mut ok) = (0, 0);
    for h in handles {
        let (a, b) = h.join().expect("a fuzz thread panicked: see above");
        n += a;
        ok += b;
    }
    println!("{n} inputs in {secs} s on {threads} threads, {ok} accepted, no disagreement");
}
