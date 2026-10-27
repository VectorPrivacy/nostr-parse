//! Parses every line of an ndjson file of events, round after round, and prints
//! ns/event: a loop to profile, not a benchmark to quote (nostrJsonBench is that).
//!
//!   cargo run --release --example corpus -- path/to/all.ndjson [seconds]

use std::hint::black_box;
use std::time::{Duration, Instant};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("an ndjson file of events");
    let secs: f64 = args.next().map_or(5.0, |s| s.parse().expect("seconds"));
    let text = std::fs::read_to_string(&path).expect("readable UTF-8");
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    let mut p = nostr_parse::Parser::new();
    let (mut rounds, mut best) = (0u64, Duration::MAX);
    let end = Instant::now() + Duration::from_secs_f64(secs);
    let mut sink = 0usize;
    while Instant::now() < end {
        let t = Instant::now();
        for &l in &lines {
            let ev = p.parse(black_box(l)).expect("a valid event");
            sink = sink.wrapping_add(ev.kind as usize + ev.tags.len() + ev.content.len());
        }
        best = best.min(t.elapsed());
        rounds += 1;
    }
    println!(
        "{} events, {rounds} rounds, best {:.1} ns/event (sink {sink})",
        lines.len(),
        best.as_nanos() as f64 / lines.len() as f64
    );
}
