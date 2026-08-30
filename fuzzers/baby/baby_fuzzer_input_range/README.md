# Baby fuzzer: input-range map

A minimal LibAFL fuzzer demonstrating an **input-range map** — a map that records, per edge,
the *range of values* that flowed through it, rather than whether (or how often) it was hit.

## The map

One byte per edge, packing two 4-bit bucket indices:

```
bit  7 6 5 4 | 3 2 1 0
     hi bkt  | lo bkt
```

* low nibble — the **lowest** value bucket ever observed at that edge
* high nibble — the **highest**

Values are bucketed with AFL-style log2 classes (`libafl::observers::range_map::range_bucket`):
`0..=3` map to themselves, then `4..=7 -> 4`, `8..=15 -> 5`, ..., saturating at `8192.. -> 15`.
Resolution is finest on small values, which is where byte- and length-shaped operands live.

The "nothing observed yet" state is `RANGE_EMPTY` (`0x0F`) — the inverted interval `lo = 15,
hi = 0`. No real observation can produce it, and since a union takes the `min` of the low
nibbles and the `max` of the high nibbles, it is absorbed by any real range with no special
casing. It is also the observer's `initial()`, so untouched edges are skipped by `MapFeedback`
for free.

## The pieces

| Piece | Where |
| --- | --- |
| `range_bucket` / `pack_range` / `unpack_range` / `range_union` / `range_map_record` | `libafl::observers::range_map` |
| `InputRangeMapObserver<M>` | `libafl::observers` |
| `RangeUnionReducer`, `InputRangeMapFeedback<C, O>` | `libafl::feedbacks` |

`InputRangeMapObserver` wraps any `u8`-valued `MapObserver` (here a `ConstMapObserver`) and
overrides exactly two methods — `initial()` and `reset_map()` — so that "unset" means
`RANGE_EMPTY` rather than `0`. Everything else (storage, serde, slice access) is inherited.

`InputRangeMapFeedback` is `MapFeedback<C, DifferentIsNovel, O, RangeUnionReducer>`. No
dedicated `IsNovel` is needed: `MapFeedback` evaluates
`is_novel(existing, reduce(existing, observed))`, and because the union is monotone the
reduced value differs from the history entry *exactly* when `lo` was pushed down or `hi` was
pushed up. "Different" and "widened" are the same predicate here.

## The target

The harness matches an `ab` prefix and then counts the run of `+` characters that follows.
The bug fires once that run reaches 32.

Nothing about the *path* changes as the run grows — after `ab` is matched the edge map is
saturated, so plain coverage keeps no intermediate progress and would have to guess the whole
run in one mutation. The range map records the run length at edge 3, and every log2 bucket it
climbs is a corpus checkpoint the fuzzer can build on.

The feedback is `feedback_or!(MaxMapFeedback, InputRangeMapFeedback)` — the range map runs
*on top of* coverage, not instead of it. Both show up in the monitor line as
`signals: n/16` and `ranges: n/16`.

## Running

```sh
cargo run
```

It fuzzes until the bug is reached, then prints the decoded range map for the crashing input
and the accumulated per-edge ranges for the whole campaign. Crashing inputs land in
`./crashes`.

Note the accumulated map comes from the feedback's history map, which `MapFeedback` only
updates when a testcase enters the *corpus* — solutions are not merged into it, so the final
dump shows the ranges the fuzzer built on, one bucket short of the crashing value.

## Wiring this to a real target

`range_set` in `src/main.rs` marks the seam. For an instrumented target, a
`__sanitizer_cov_trace_cmp*` hook in `libafl_targets` would call `range_map_record` with the
current edge id and each compared operand, the way the cmplog runtime does today. Nothing in
the observer or feedback is specific to a hand-written harness.
