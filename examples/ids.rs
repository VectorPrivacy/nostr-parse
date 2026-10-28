//! Event ids: rust-nostr's way (`serde_json::to_vec` of the NIP-01 tuple, then
//! SHA-256 of the buffer) against `write_preimage` streaming into the same
//! SHA-256 engine, on the event shapes a chat client checks most. Both hash
//! with sha2 0.11, so the difference is the serialization alone.
//!
//!   cargo run --release --example ids [rounds]

use sha2::{Digest, Sha256};
use std::hint::black_box;
use std::time::Instant;

fn base64ish(n: usize) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    (0..n).map(|i| A[(i * 7919 + i / 3) % 64] as char).collect()
}

fn event(content: String, tags: Vec<Vec<String>>) -> nostr_parse::Event {
    nostr_parse::Event { id: [0; 32], pubkey: [0x37; 32], created_at: 1_761_600_000, kind: 1059, tags, content, sig: Some([0; 64]) }
}

fn main() {
    let rounds: usize = std::env::args().nth(1).map_or(31, |s| s.parse().expect("rounds"));
    let p = |c: char| vec!["p".to_string(), c.to_string().repeat(64)];
    let article = "## A heading\n\nSome \"quoted\" text, a [link](https://vectorapp.io/?a=1&b=2) and a tab\there.\n".repeat(120);
    let cases = [
        ("gift wrap, 1.6 KB base64", event(base64ish(1_600), vec![p('7')])),
        ("seal, 700 B base64", event(base64ish(700), vec![])),
        ("note, 200 B, 5 tags", event("gm \"nostr\" 🚀\nhave a great day ".repeat(6), (0..5).map(|i| p(char::from(b'a' + i))).collect())),
        ("article, 10 KB with escapes", event(article, vec![vec!["d".into(), "my-article".into()], vec!["title".into(), "A title".into()]])),
    ];
    println!("ns per id, median of {rounds} rounds");
    println!("  {:<30} {:>12} {:>12} {:>8}", "event", "serde_json", "streamed", "faster");
    for (name, ev) in &cases {
        let pubkey: String = ev.pubkey.iter().map(|b| format!("{b:02x}")).collect();
        let theirs = || {
            let buf = serde_json::to_vec(&(0u8, &pubkey, ev.created_at, ev.kind, &ev.tags, &ev.content)).unwrap();
            Sha256::digest(&buf)
        };
        let ours = || {
            let mut h = Sha256::new();
            ev.write_preimage(|b| h.update(b));
            h.finalize()
        };
        assert_eq!(theirs(), ours(), "{name}");
        let n = 2_000;
        let mut t = (Vec::new(), Vec::new());
        for round in 0..rounds {
            for first in [round % 2 == 0, round % 2 == 1] {
                let start = Instant::now();
                for _ in 0..n {
                    if first {
                        black_box(theirs());
                    } else {
                        black_box(ours());
                    }
                }
                let ns = start.elapsed().as_nanos() as f64 / n as f64;
                if first { t.0.push(ns) } else { t.1.push(ns) }
            }
        }
        let med = |v: &mut Vec<f64>| {
            v.sort_by(f64::total_cmp);
            v[v.len() / 2]
        };
        let (a, b) = (med(&mut t.0), med(&mut t.1));
        println!("  {name:<30} {a:>12.0} {b:>12.0} {:>7.2}x", a / b);
    }
}
