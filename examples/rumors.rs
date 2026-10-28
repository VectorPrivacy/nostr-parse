//! NIP-59 rumors (kind 14 DMs, as rust-nostr writes them: id first, no sig),
//! read by rust-nostr's `UnsignedEvent::from_json` and by `parse_unsigned`,
//! alone and converted into rust-nostr's type. Also what a refusal costs: one
//! `parse_unsigned` gives back to rust-nostr (an uppercase id), and the signed
//! reader turning a rumor away for its missing sig, as 0.2 had to.
//!
//!   cargo run --release --example rumors [rounds]

use std::hint::black_box;
use std::time::Instant;

use nostr::prelude::{EventId, Kind, PublicKey, Tag, Timestamp, UnsignedEvent};

const N: usize = 2000;

fn content(i: usize) -> String {
    let base = "Hey, did you see the \"new\" build? It's really fast 🚀 — check https://vectorapp.io/?a=1&b=2 later\n";
    match i % 10 {
        0..=5 => base[..30].to_string(),
        6..=8 => base.repeat(2),
        _ => base.repeat(16),
    }
}

/// `n` DM rumors from eight senders to one recipient, a quarter of them replies.
fn rumors(n: usize) -> Vec<String> {
    let key = |i: u8| PublicKey::from_byte_array([i; 32]);
    let me = key(1).to_hex();
    (0..n)
        .map(|i| {
            let mut tags = vec![Tag::parse(["p", me.as_str()]).unwrap()];
            if i % 4 == 0 {
                tags.push(Tag::parse(["e", &"7".repeat(64), "", "reply"]).unwrap());
            }
            let mut r = UnsignedEvent::new(key(2 + (i % 8) as u8), Timestamp::from(1_761_600_000 + i as u64), Kind::from(14u16), tags, content(i));
            r.ensure_id();
            r.as_json()
        })
        .collect()
}

fn to_nostr(e: nostr_parse::UnsignedEvent) -> Option<UnsignedEvent> {
    let tags: Vec<Tag> = e.tags.into_iter().map(Tag::parse).collect::<Result<_, _>>().ok()?;
    let mut ev = UnsignedEvent::new(PublicKey::from_byte_array(e.pubkey), Timestamp::from(e.created_at), Kind::from(e.kind), tags, e.content);
    ev.id = e.id.map(EventId::from_byte_array);
    Some(ev)
}

fn main() {
    let rounds: usize = std::env::args().nth(1).map_or(31, |s| s.parse().expect("rounds"));
    let docs = rumors(N);
    let upper: Vec<String> = docs
        .iter()
        .map(|d| {
            let at = d.find("\"id\":\"").unwrap() + 6;
            format!("{}{}{}", &d[..at], d[at..at + 64].to_uppercase(), &d[at + 64..])
        })
        .collect();
    let avg = docs.iter().map(String::len).sum::<usize>() / N;
    let mut p = nostr_parse::Parser::new();

    // Same answers before any timing.
    for d in &docs {
        let ours = p.parse_unsigned(d).ok().and_then(to_nostr).expect("nostr-parse reads every rumor");
        assert_eq!(Some(ours), UnsignedEvent::from_json(d).ok(), "{d}");
    }
    assert!(upper.iter().all(|d| p.parse_unsigned(d).is_err()));

    type Row<'a> = (&'static str, Box<dyn FnMut(&mut nostr_parse::Parser) + 'a>);
    let mut rows: Vec<Row<'_>> = vec![
        ("rust-nostr UnsignedEvent::from_json", Box::new(|_: &mut nostr_parse::Parser| for d in &docs { black_box(UnsignedEvent::from_json(black_box(d)).unwrap()); })),
        ("nostr-parse parse_unsigned", Box::new(|p: &mut nostr_parse::Parser| for d in &docs { black_box(p.parse_unsigned(black_box(d)).unwrap()); })),
        ("parse_unsigned, into rust-nostr's type", Box::new(|p: &mut nostr_parse::Parser| for d in &docs { black_box(to_nostr(p.parse_unsigned(black_box(d)).unwrap())); })),
        ("refused: parse_unsigned, uppercase id", Box::new(|p: &mut nostr_parse::Parser| for d in &upper { black_box(p.parse_unsigned(black_box(d)).is_err()); })),
        ("refused: signed parse, no sig (0.2)", Box::new(|p: &mut nostr_parse::Parser| for d in &docs { black_box(p.parse(black_box(d)).is_err()); })),
    ];
    let mut ns: Vec<Vec<f64>> = vec![Vec::new(); rows.len()];
    for round in 0..rounds {
        // A different row first each round, so none always runs warm or cold.
        for k in 0..rows.len() {
            let i = (round + k) % rows.len();
            let t = Instant::now();
            (rows[i].1)(&mut p);
            ns[i].push(t.elapsed().as_nanos() as f64 / N as f64);
        }
    }
    println!("{N} DM rumors, {avg} B on average; ns per rumor, median of {rounds} rounds");
    for ((name, _), v) in rows.iter().zip(ns.iter_mut()) {
        v.sort_by(f64::total_cmp);
        println!("  {name:<40} {:>7.0}", v[v.len() / 2]);
    }
}
