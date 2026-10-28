<h1 align="center">nostr-parse</h1>

<p align="center">
  <b>Nostr events, parsed fast.</b><br>
  A strict NIP-01 event parser in Rust. No dependencies, SIMD where it counts, one allocation per event.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2a78d6"></a>
  <img alt="Rust 1.85 or newer" src="https://img.shields.io/badge/rust-1.85%2B-2a78d6">
  <img alt="Zero dependencies" src="https://img.shields.io/badge/dependencies-0-2a78d6">
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="bench/macos-dark.svg">
  <img alt="Bar chart: nanoseconds per event on Apple M4 Max. nostr-parse CompactEvent is fastest, ahead of Kite, sonic-rs, serde_json, simd-json, simdjson and rust-nostr; the table below has every number." src="bench/macos-light.svg">
</picture>

- **1.9–2.7× faster than Kite**, the hand-written JVM parser in
  [Amethyst](https://github.com/vitorpamplona/amethyst)'s Quartz library, on every workload on
  both machines measured.
- **3.0–3.7× faster than serde_json, sonic-rs, simd-json and simdjson** when each builds owned,
  decoded events, and 4.4–4.7× faster than rust-nostr's `Event::from_json`.
- **One allocation per event** with `CompactEvent`, however many tags it carries. The others
  make 14 to 21.

## Install

Not on crates.io yet:

```toml
[dependencies]
nostr-parse = { git = "https://github.com/VectorPrivacy/nostr-parse" }
```

## Use

```rust
let mut parser = nostr_parse::Parser::new(); // keep it: its scratch space carries over

let event = parser.parse_compact(json)?;
println!("kind {} by {:02x?}…", event.kind, &event.pubkey[..4]);
println!("{}", event.content());
for tag in event.tags().iter() {
    println!("{:?} = {:?}", tag.name(), tag.get(1));
}
```

`nostr_parse::parse` and `nostr_parse::parse_compact` do the same with a fresh parser each call.

### Two shapes of the same event

| | tags and content | allocations | for |
|---|---|---|---|
| `CompactEvent` | one heap block, read through `content()` and `tags()` | 1 | reading: clients, relays, indexers |
| `Event` | `Vec<Vec<String>>` and a `String` | one per string | changing an event, or handing it to another library |

Both keep id and pubkey as `[u8; 32]`, sig as `Option<[u8; 64]>` (`None` for `""`, an unsigned
event such as a NIP-59 rumor), and `created_at` and `kind` as integers.

### Into rust-nostr

`Event` has the same shape as rust-nostr's, so converting moves the strings instead of copying
them:

```rust
use nostr::prelude::*;

fn to_nostr(e: nostr_parse::Event) -> Option<Event> {
    let tags: Vec<Tag> = e.tags.into_iter().map(Tag::parse).collect::<Result<_, _>>().ok()?;
    Some(Event::new(
        EventId::from_byte_array(e.id),
        PublicKey::from_byte_array(e.pubkey),
        Timestamp::from(e.created_at),
        Kind::from(e.kind),
        tags,
        e.content,
        Signature::from_byte_array(e.sig?),
    ))
}
```

Parsing and converting this way is still 2.4–2.8× faster than `Event::from_json` (the
"nostr-parse → rust-nostr" row below).

## Benchmarks

Measured with [nostrJsonBench](https://github.com/vitorpamplona/nostrJsonBench), Vitor Pamplona's
cross-language harness. Its corpus is 31,161 real events, timed together (`all`) and split into
seven workloads by kind. Its rules are strict:
- every parser produces owned, fully decoded events;
- every output is checked against a reference digest, and a parser whose output differs isn't
  ranked.

Each machine ran three rounds, alternating the JVM and Rust harnesses. The figures are medians.

### macOS · Apple M4 Max

<!-- bench:macos:speed -->
| ns per event | all | notes | reactions | dms | giftwraps | metadata | zaps | lists |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **nostr-parse `CompactEvent`** | **212** | **238** | **125** | **89** | **144** | **322** | **625** | **1,008** |
| **nostr-parse `Event`** | **369** | **504** | **282** | **172** | **227** | **358** | **895** | **2,025** |
| nostr-parse → rust-nostr `Event` | 388 | 526 | 305 | 189 | 245 | 377 | 912 | 2,048 |
| Kite, Quartz 2.2.0 (JVM) | 406 | 457 | 262 | 210 | 333 | 685 | 956 | 1,640 |
| sonic-rs 0.5.10 | 628 | 851 | 486 | 317 | 458 | 785 | 1,488 | 2,824 |
| serde_json 1.0.154 | 720 | 921 | 531 | 383 | 518 | 936 | 1,707 | 3,165 |
| simd-json 0.18.1 | 760 | 939 | 574 | 451 | 672 | 763 | 1,600 | 3,976 |
| simdjson-rust 0.4.0-alpha.2 (C++ simdjson) | 791 | 1,010 | 606 | 481 | 661 | 707 | 1,485 | 3,925 |
| rust-nostr 0.45.5 `Event::from_json` | 929 | 1,123 | 704 | 514 | 667 | 1,066 | 1,875 | 3,700 |
<!-- /bench -->

`CompactEvent` is the fastest on every workload. The plain `Event` pays one allocation per
string, where the JVM allocates almost for free, so Kite still beats it on notes, reactions and
lists here, and on lists on x86-64.

### Linux x86-64 · Intel Core i7-6700

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="bench/x86-dark.svg">
  <img alt="Bar chart: nanoseconds per event on an Intel Core i7-6700. nostr-parse CompactEvent is fastest; the table below has every number." src="bench/x86-light.svg">
</picture>

<!-- bench:x86:speed -->
| ns per event | all | notes | reactions | dms | giftwraps | metadata | zaps | lists |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **nostr-parse `CompactEvent`** | **324** | **381** | **207** | **170** | **295** | **514** | **832** | **1,497** |
| **nostr-parse `Event`** | **515** | **711** | **365** | **247** | **359** | **544** | **1,034** | **3,878** |
| nostr-parse → rust-nostr `Event` | 554 | 753 | 398 | 282 | 392 | 569 | 1,072 | 3,963 |
| Kite, Quartz 2.2.0 (JVM) | 875 | 1,068 | 583 | 421 | 564 | 1,697 | 2,135 | 3,206 |
| sonic-rs 0.5.10 | 991 | 1,336 | 719 | 488 | 680 | 1,167 | 2,093 | 6,047 |
| simd-json 0.18.1 | 1,062 | 1,454 | 833 | 637 | 883 | 886 | 1,771 | 7,370 |
| serde_json 1.0.154 | 1,100 | 1,394 | 748 | 549 | 768 | 1,565 | 2,463 | 6,729 |
| simdjson-rust 0.4.0-alpha.2 (C++ simdjson) | 1,183 | 1,556 | 889 | 718 | 948 | 1,061 | 1,807 | 7,496 |
| rust-nostr 0.45.5 `Event::from_json` | 1,525 | 1,856 | 1,066 | 793 | 1,045 | 1,909 | 2,827 | 7,956 |
<!-- /bench -->

### Memory

The same runs on macOS, per event over all events:

<!-- bench:macos:memory -->
| per event, all events | allocations | bytes allocated | objects kept | bytes kept |
|---|---:|---:|---:|---:|
| **nostr-parse `CompactEvent`** | 1.0 | 534 | 1.0 | 702 |
| **nostr-parse `Event`** | 11.1 | 724 | 11.1 | 916 |
| nostr-parse → rust-nostr `Event` | 11.1 | 724 | 11.1 | 916 |
| Kite, Quartz 2.2.0 (JVM) | 21.3 | 1,321 | 21.4 | 1,289 |
| sonic-rs 0.5.10 | 15.8 | 1,675 | 14.0 | 1,281 |
| serde_json 1.0.154 | 15.4 | 1,644 | 14.0 | 1,281 |
| simd-json 0.18.1 | 15.3 | 2,705 | 14.0 | 1,109 |
| simdjson-rust 0.4.0-alpha.2 (C++ simdjson) | 14.0 | 973 | 14.0 | 1,109 |
| rust-nostr 0.45.5 `Event::from_json` | 16.3 | 1,687 | 11.1 | 1,087 |
<!-- /bench -->

The Rust rows count heap allocations, and Kite's row counts JVM objects. Bytes compare across
the two; object counts only within a runtime.

### Setup

- **Rust:** release builds (fat LTO, one codegen unit). rustc 1.95 with default flags on macOS;
  rustc 1.98 with `-C target-cpu=native` on x86-64.
- **JVM:** Kite ran with Quartz 2.2.0 on OpenJDK 21.0.13, G1 and `-Xmx2g`: Homebrew's build on
  macOS, Temurin on x86-64.
- **x86-64:** both harnesses were pinned to one core.
- **Harness:** nostr-parse's rows aren't in upstream nostrJsonBench yet; they are three small
  entries in its Rust harness.
- **Raw data:** `bench/results.json` holds the medians, `bench/summarize.py` builds it from
  nostrJsonBench's output, and `bench/chart.py` and `bench/tables.py` draw the charts and tables
  above.

## Strict

The input must be one JSON object holding the seven NIP-01 fields once each. Other keys are
checked and skipped. The fields themselves:
- **id and pubkey:** 64 lowercase hex digits (JSON escapes allowed, as serde_json allows them).
- **sig:** 128 lowercase hex digits, or `""`.
- **created_at and kind:** plain non-negative integers; kind fits a `u16`.
- **tags:** arrays of strings.

Strings are fully unescaped, and a lone surrogate is refused. An error gives a message and the
byte offset where parsing stopped.

## How it's fast

- **One pass, no tree.** Fields are written straight into the event. Common key order takes a
  fast path; any order still parses.
- **16 bytes at a time.** String ends are found with NEON on aarch64 and SSE2 on x86-64, and
  scalar code everywhere else, wasm32 included.
- **Hex straight to bytes.** id, pubkey and sig are decoded 32 digits at a time into fixed
  arrays, with no strings in between.
- **Exact-size allocations.** Every string and list is allocated once, at its final size. A
  `CompactEvent` is a single allocation.

## Tested

- **Differential tests against serde_json:** every edge case, an escape at every offset of a
  16-byte block, and refusals with the same error from both shapes.
- **A generation-based fuzzer:** random events in every spelling, edits of them, and arbitrary
  JSON, against a serde_json reader of the same rules. About 52 million inputs, on arm64 and
  x86-64, without a disagreement.

```bash
cargo test --release
FUZZ_SECS=600 cargo test --release --test fuzz -- --ignored --nocapture
```

## Minimum Rust

1.85.

## License

MIT, see [LICENSE](LICENSE).

Thanks to Vitor Pamplona, whose Kite and nostrJsonBench set the bar this was built to clear.
