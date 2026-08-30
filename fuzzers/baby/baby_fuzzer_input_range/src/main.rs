//! A baby fuzzer demonstrating an *input-range map*.
//!
//! Alongside the usual edge map, this fuzzer keeps a second map of the same shape in which
//! each entry records the *range of values* observed there, packed into one byte as two
//! 4-bit log2 buckets (low nibble = lowest bucket, high nibble = highest).
//!
//! The artificial bug is gated on a value, not on a path: once the `ab` prefix is matched,
//! plain edge coverage is saturated and gives the fuzzer nothing more to chase. The range
//! map keeps rewarding inputs that push the observed run length higher, and that gradient
//! is what drives the fuzzer to the crash.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

use libafl::{
    HasNamedMetadata,
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, InProcessExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, InputRangeMapFeedback, MapFeedbackMetadata, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::{
        ConstMapObserver, InputRangeMapObserver,
        range_map::{RANGE_EMPTY, range_map_record, unpack_range},
    },
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasSolutions, StdState},
};
use libafl_bolts::{
    Named, current_nanos, nonnull_raw_mut, nonzero, rands::StdRand, tuples::tuple_list,
};

/// Number of entries in both maps. In a real target this would be the edge count.
const MAP_LEN: usize = 16;

/// How long a run of `+` after the `ab` prefix is needed to trigger the bug.
///
/// Nothing about the *path* changes as this run grows, so plain edge coverage keeps no
/// intermediate progress and would have to guess the whole run at once. The range map
/// records the run length at edge 3, and every bucket it climbs is a corpus checkpoint.
const RUN_TARGET: u64 = 32;

/// The classic coverage map: one byte per edge, "was it hit".
static mut SIGNALS: [u8; MAP_LEN] = [0; MAP_LEN];
static mut SIGNALS_PTR: *mut u8 = &raw mut SIGNALS as _;

/// The input-range map: one byte per edge, "which values passed through it".
static mut RANGES: [u8; MAP_LEN] = [RANGE_EMPTY; MAP_LEN];
static mut RANGES_PTR: *mut u8 = &raw mut RANGES as _;

/// Guards the one-shot report printed when the bug is first reached.
static REPORTED: AtomicBool = AtomicBool::new(false);

/// Mark an edge as hit.
fn signals_set(idx: usize) {
    unsafe { *SIGNALS_PTR.add(idx) = 1 };
}

/// Record a value observed at an edge, widening that edge's range.
///
/// This is the seam a real target would drive from instrumentation: a
/// `__sanitizer_cov_trace_cmp*` hook in `libafl_targets` would call
/// [`range_map_record`] with the current edge id and each compared operand, exactly
/// the way the cmplog runtime does today.
fn range_set(idx: usize, value: u64) {
    range_map_record(
        unsafe { std::slice::from_raw_parts_mut(RANGES_PTR, MAP_LEN) },
        idx,
        value,
    );
}

/// Print the decoded contents of a packed input-range map.
fn print_ranges(label: &str, map: &[u8]) {
    println!("{label}:");
    for (idx, packed) in map.iter().enumerate() {
        match unpack_range(*packed) {
            None => println!("  edge {idx:2}: -"),
            Some((lo, hi)) => println!("  edge {idx:2}: buckets {lo}..={hi} ({packed:#04x})"),
        }
    }
}

pub fn main() {
    env_logger::init();

    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = &target;

        signals_set(0);
        range_set(0, buf.len() as u64);

        if !buf.is_empty() && buf[0] == b'a' {
            signals_set(1);
            // Edges 1 and 2 only ever see one value, which the range map reports as a
            // degenerate `lo == hi` interval -- itself a useful readout.
            range_set(1, u64::from(buf[0]));

            if buf.len() > 1 && buf[1] == b'b' {
                signals_set(2);
                range_set(2, u64::from(buf[1]));

                // From here on the edge map is saturated: every further input takes the
                // exact same path, so coverage gives the fuzzer nothing more to chase.
                // Only the *value* changes, and only the range map can see that.
                let run = buf[2..].iter().take_while(|&&b| b == b'+').count() as u64;
                range_set(3, run);

                if run >= RUN_TARGET {
                    // Demo-only: a real harness must never do I/O. One-shot, so the
                    // stream is not flooded once the fuzzer starts finding this easily.
                    if !REPORTED.swap(true, Ordering::Relaxed) {
                        print_ranges(
                            "\nArtificial bug triggered =) ranges for the first crashing input",
                            unsafe { std::slice::from_raw_parts(RANGES_PTR, MAP_LEN) },
                        );
                    }
                    return ExitKind::Crash;
                }
            }
        }
        ExitKind::Ok
    };

    // The plain coverage observation channel
    let signals_observer =
        unsafe { ConstMapObserver::from_mut_ptr("signals", nonnull_raw_mut!(SIGNALS)) };

    // The input-range observation channel over the same-shaped map.
    // The wrapper is what makes `RANGE_EMPTY` (not `0`) mean "nothing observed".
    let ranges_observer = InputRangeMapObserver::new(unsafe {
        ConstMapObserver::from_mut_ptr("ranges", nonnull_raw_mut!(RANGES))
    });
    let ranges_name = ranges_observer.name().clone();

    // Feedback to rate the interestingness of an input.
    // The range feedback runs *on top of* coverage, not instead of it.
    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&signals_observer),
        InputRangeMapFeedback::new(&ranges_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::new(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let mon = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(mon);

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(signals_observer, ranges_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(nonzero!(32));

    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // Fuzz in chunks so we can stop and report once the value-gated bug is reached.
    while state.solutions().is_empty() {
        fuzzer
            .fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 100)
            .expect("Error in the fuzzing loop");
    }

    // The union of every range ever observed lives in the range feedback's history map.
    let history = state
        .named_metadata::<MapFeedbackMetadata<u8>>(&ranges_name)
        .expect("no history map for the range feedback");
    print_ranges(
        "\nAccumulated input ranges across the whole campaign",
        &history.history_map,
    );
}
