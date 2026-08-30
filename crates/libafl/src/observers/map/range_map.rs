//! Input-range map observer.
//!
//! Where a coverage map answers *"was this edge hit, and roughly how often?"*, an
//! **input-range map** answers *"what values flowed through this edge?"*. Each map
//! entry is a single `u8` packing two 4-bit bucket indices:
//!
//! ```text
//! bit  7 6 5 4 | 3 2 1 0
//!      hi bkt  | lo bkt
//! ```
//!
//! The low nibble is the *lowest* value bucket ever observed at that entry, the high
//! nibble the *highest*. A testcase is interesting when it widens some entry's range;
//! see [`crate::feedbacks::InputRangeMapFeedback`].
//!
//! Values are bucketed with AFL-style log2 classes ([`range_bucket`]) so the encoding
//! also works for operands much wider than a byte.
//!
//! The "no observation yet" state is [`RANGE_EMPTY`], the inverted interval
//! `lo = 15, hi = 0`. No real observation can produce it, and because a union takes the
//! `min` of the low nibbles and the `max` of the high nibbles, it is absorbed by any
//! real range without a special case.

use alloc::{borrow::Cow, vec::Vec};
use core::{
    fmt::{self, Debug},
    hash::Hash,
    ops::{Deref, DerefMut},
};

use libafl_bolts::{HasLen, Named, ToSlice, ToSliceMut, Truncate};
use serde::{Deserialize, Serialize};

use crate::{
    Error,
    executors::ExitKind,
    observers::{
        ConstLenMapObserver, DifferentialObserver, Observer, VarLenMapObserver, map::MapObserver,
    },
};

/// The "no value observed yet" entry: the inverted interval `lo = 15, hi = 0`.
///
/// This is the [`MapObserver::initial`] value of an [`InputRangeMapObserver`], so
/// untouched entries are skipped by [`crate::feedbacks::MapFeedback`] for free.
pub const RANGE_EMPTY: u8 = 0x0F;

/// The number of distinct value buckets (one nibble).
pub const RANGE_BUCKETS: u8 = 16;

/// Bucket a value into one of [`RANGE_BUCKETS`] AFL-style log2 classes.
///
/// `0..=3` map to themselves, then each power-of-two class gets its own bucket:
/// `4..=7 -> 4`, `8..=15 -> 5`, ..., saturating at `8192.. -> 15`. Resolution is
/// finest on small values, which is where byte- and length-shaped operands live.
#[must_use]
pub const fn range_bucket(value: u64) -> u8 {
    match value {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        _ => {
            // `value >= 4`, so `ilog2(value) >= 2` and the class is at least 4.
            let class = value.ilog2() as u8 + 2;
            if class > RANGE_BUCKETS - 1 {
                RANGE_BUCKETS - 1
            } else {
                class
            }
        }
    }
}

/// Pack a `lo`/`hi` bucket pair into a single map entry.
///
/// Only the low nibble of each argument is used.
#[must_use]
pub const fn pack_range(lo: u8, hi: u8) -> u8 {
    ((hi & 0x0F) << 4) | (lo & 0x0F)
}

/// Decode a map entry into its `(lo, hi)` bucket pair, or [`None`] if nothing has been
/// observed at that entry yet.
#[must_use]
pub fn unpack_range(packed: u8) -> Option<(u8, u8)> {
    if packed == RANGE_EMPTY {
        return None;
    }
    let lo = packed & 0x0F;
    let hi = packed >> 4;
    debug_assert!(lo <= hi, "malformed input-range entry {packed:#04x}: lo > hi");
    Some((lo, hi))
}

/// Union two map entries: the `min` of the low nibbles and the `max` of the high nibbles.
///
/// [`RANGE_EMPTY`] is the identity element.
#[must_use]
pub const fn range_union(a: u8, b: u8) -> u8 {
    let lo_a = a & 0x0F;
    let lo_b = b & 0x0F;
    let hi_a = a >> 4;
    let hi_b = b >> 4;

    let lo = if lo_a < lo_b { lo_a } else { lo_b };
    let hi = if hi_a > hi_b { hi_a } else { hi_b };
    pack_range(lo, hi)
}

/// Record `value` as observed at `idx`, widening that entry's range in place.
///
/// Out-of-bounds indexes are ignored, mirroring how coverage runtimes mask edge ids.
/// This is the function a target-side hook (for example a `__sanitizer_cov_trace_cmp*`
/// callback in `libafl_targets`) would call for every compared operand.
#[inline]
pub fn range_map_record(map: &mut [u8], idx: usize, value: u64) {
    if let Some(entry) = map.get_mut(idx) {
        let bucket = range_bucket(value);
        *entry = range_union(*entry, pack_range(bucket, bucket));
    }
}

/// Map observer tracking the *range of values* seen at each entry rather than hitcounts.
///
/// This wraps any `u8`-valued [`MapObserver`] (such as
/// [`ConstMapObserver`](crate::observers::ConstMapObserver) or
/// [`StdMapObserver`](crate::observers::StdMapObserver)), which keeps all of the storage,
/// serialization and slice plumbing, and overrides only the two methods that carry the
/// range semantics: [`MapObserver::initial`] and [`MapObserver::reset_map`] both use
/// [`RANGE_EMPTY`] instead of the base observer's initial value.
///
/// Pair it with [`crate::feedbacks::InputRangeMapFeedback`].
#[derive(Serialize, Deserialize, Clone, Hash)]
pub struct InputRangeMapObserver<M> {
    base: M,
}

impl<M> InputRangeMapObserver<M> {
    /// Wrap a `u8`-valued [`MapObserver`] as an input-range map.
    pub fn new(base: M) -> Self {
        Self { base }
    }

    /// The wrapped observer.
    pub fn base(&self) -> &M {
        &self.base
    }
}

impl<M> InputRangeMapObserver<M>
where
    M: MapObserver<Entry = u8>,
{
    /// Iterate the entries that have seen at least one value, as `(index, lo, hi)`.
    pub fn ranges(&self) -> impl Iterator<Item = (usize, u8, u8)> + '_ {
        (0..self.base.usable_count())
            .filter_map(|idx| unpack_range(self.base.get(idx)).map(|(lo, hi)| (idx, lo, hi)))
    }
}

impl<M> Debug for InputRangeMapObserver<M>
where
    M: MapObserver<Entry = u8> + Named,
{
    /// Prints decoded `idx: lo..=hi` intervals; the raw packed bytes are unreadable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InputRangeMapObserver {{ name: {:?}, ranges: {{", self.name())?;
        for (i, (idx, lo, hi)) in self.ranges().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            write!(f, " {idx}: {lo}..={hi}")?;
        }
        write!(f, " }} }}")
    }
}

impl<M> Deref for InputRangeMapObserver<M> {
    type Target = M;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl<M> DerefMut for InputRangeMapObserver<M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

impl<I, S, M> Observer<I, S> for InputRangeMapObserver<M>
where
    M: MapObserver<Entry = u8> + Observer<I, S> + for<'a> ToSliceMut<'a, Entry = u8>,
{
    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        self.base.flush()
    }

    /// Resets to [`RANGE_EMPTY`].
    ///
    /// Note this deliberately does *not* delegate to `base.pre_exec`, which would reset
    /// the map to the base observer's initial value (typically `0`, a valid range).
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()
    }

    #[inline]
    fn post_exec(&mut self, state: &mut S, input: &I, exit_kind: &ExitKind) -> Result<(), Error> {
        self.base.post_exec(state, input, exit_kind)
    }
}

impl<M> Named for InputRangeMapObserver<M>
where
    M: Named,
{
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.base.name()
    }
}

impl<M> HasLen for InputRangeMapObserver<M>
where
    M: HasLen,
{
    #[inline]
    fn len(&self) -> usize {
        self.base.len()
    }
}

impl<M> AsRef<Self> for InputRangeMapObserver<M> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<M> AsMut<Self> for InputRangeMapObserver<M> {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl<M> MapObserver for InputRangeMapObserver<M>
where
    M: MapObserver<Entry = u8>,
{
    type Entry = u8;

    /// [`RANGE_EMPTY`], *not* the base observer's initial value.
    #[inline]
    fn initial(&self) -> u8 {
        RANGE_EMPTY
    }

    #[inline]
    fn usable_count(&self) -> usize {
        self.base.usable_count()
    }

    #[inline]
    fn get(&self, idx: usize) -> u8 {
        self.base.get(idx)
    }

    #[inline]
    fn set(&mut self, idx: usize, val: u8) {
        self.base.set(idx, val);
    }

    /// Count the entries that have observed at least one value.
    fn count_bytes(&self) -> u64 {
        let cnt = self.usable_count();
        let mut res = 0;
        for idx in 0..cnt {
            if self.base.get(idx) != RANGE_EMPTY {
                res += 1;
            }
        }
        res
    }

    /// Reset every entry to [`RANGE_EMPTY`].
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        let cnt = self.usable_count();
        for idx in 0..cnt {
            self.base.set(idx, RANGE_EMPTY);
        }
        Ok(())
    }

    fn to_vec(&self) -> Vec<u8> {
        self.base.to_vec()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        let cnt = self.usable_count();
        let mut res = 0;
        for i in indexes {
            if *i < cnt && self.base.get(*i) != RANGE_EMPTY {
                res += 1;
            }
        }
        res
    }
}

impl<M, const N: usize> ConstLenMapObserver<N> for InputRangeMapObserver<M>
where
    M: ConstLenMapObserver<N> + MapObserver<Entry = u8>,
{
    fn map_slice(&self) -> &[Self::Entry; N] {
        self.base.map_slice()
    }

    fn map_slice_mut(&mut self) -> &mut [Self::Entry; N] {
        self.base.map_slice_mut()
    }
}

impl<M> VarLenMapObserver for InputRangeMapObserver<M>
where
    M: VarLenMapObserver + MapObserver<Entry = u8>,
{
    fn map_slice(&self) -> &[Self::Entry] {
        self.base.map_slice()
    }

    fn map_slice_mut(&mut self) -> &mut [Self::Entry] {
        self.base.map_slice_mut()
    }

    fn size(&self) -> &usize {
        self.base.size()
    }

    fn size_mut(&mut self) -> &mut usize {
        self.base.size_mut()
    }
}

impl<M> Truncate for InputRangeMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + Truncate,
{
    fn truncate(&mut self, new_len: usize) {
        self.base.truncate(new_len);
    }
}

impl<'a, M> ToSlice<'a> for InputRangeMapObserver<M>
where
    M: ToSlice<'a>,
{
    type Entry = <M as ToSlice<'a>>::Entry;
    type SliceRef = <M as ToSlice<'a>>::SliceRef;

    #[inline]
    fn to_slice(&'a self) -> Self::SliceRef {
        self.base.to_slice()
    }
}

impl<'a, M> ToSliceMut<'a> for InputRangeMapObserver<M>
where
    M: ToSliceMut<'a>,
{
    type SliceRefMut = <M as ToSliceMut<'a>>::SliceRefMut;

    #[inline]
    fn to_slice_mut(&'a mut self) -> Self::SliceRefMut {
        self.base.to_slice_mut()
    }
}

impl<M, OTA, OTB, I, S> DifferentialObserver<OTA, OTB, I, S> for InputRangeMapObserver<M>
where
    M: DifferentialObserver<OTA, OTB, I, S>
        + MapObserver<Entry = u8>
        + for<'a> ToSliceMut<'a, Entry = u8>,
{
    fn pre_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        self.base.pre_observe_first(observers)
    }

    fn post_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        self.base.post_observe_first(observers)
    }

    fn pre_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        self.base.pre_observe_second(observers)
    }

    fn post_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        self.base.post_observe_second(observers)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RANGE_EMPTY, pack_range, range_bucket, range_map_record, range_union, unpack_range,
    };

    #[test]
    fn bucket_boundaries() {
        assert_eq!(range_bucket(0), 0);
        assert_eq!(range_bucket(1), 1);
        assert_eq!(range_bucket(2), 2);
        assert_eq!(range_bucket(3), 3);
        assert_eq!(range_bucket(4), 4);
        assert_eq!(range_bucket(7), 4);
        assert_eq!(range_bucket(8), 5);
        assert_eq!(range_bucket(15), 5);
        assert_eq!(range_bucket(16), 6);
        assert_eq!(range_bucket(8191), 14);
        assert_eq!(range_bucket(8192), 15);
        assert_eq!(range_bucket(u64::MAX), 15);
    }

    #[test]
    fn bucket_is_monotone() {
        let mut last = 0;
        for v in 0..100_000u64 {
            let b = range_bucket(v);
            assert!(b >= last, "bucket decreased at {v}");
            assert!(b < 16);
            last = b;
        }
    }

    #[test]
    fn pack_unpack_roundtrip() {
        for lo in 0..16u8 {
            for hi in lo..16u8 {
                let packed = pack_range(lo, hi);
                // RANGE_EMPTY is the inverted interval lo = 15, hi = 0, so no valid
                // `lo <= hi` pair can ever collide with it
                assert_ne!(packed, RANGE_EMPTY, "valid range {lo}..={hi} hit RANGE_EMPTY");
                assert_eq!(unpack_range(packed), Some((lo, hi)));
            }
        }
    }

    #[test]
    fn empty_decodes_to_none() {
        assert_eq!(unpack_range(RANGE_EMPTY), None);
        assert_eq!(pack_range(15, 0), RANGE_EMPTY);
    }

    #[test]
    fn union_absorbs_empty() {
        for lo in 0..16u8 {
            for hi in lo..16u8 {
                let r = pack_range(lo, hi);
                assert_eq!(range_union(RANGE_EMPTY, r), r);
                assert_eq!(range_union(r, RANGE_EMPTY), r);
            }
        }
        assert_eq!(range_union(RANGE_EMPTY, RANGE_EMPTY), RANGE_EMPTY);
    }

    #[test]
    fn union_is_idempotent_commutative_and_widening() {
        for a_lo in 0..16u8 {
            for a_hi in a_lo..16u8 {
                let a = pack_range(a_lo, a_hi);
                assert_eq!(range_union(a, a), a);
                for b_lo in 0..16u8 {
                    for b_hi in b_lo..16u8 {
                        let b = pack_range(b_lo, b_hi);
                        let u = range_union(a, b);
                        assert_eq!(u, range_union(b, a));

                        let (lo, hi) = unpack_range(u).expect("union of real ranges is not empty");
                        assert!(lo <= hi);
                        assert_eq!(lo, a_lo.min(b_lo));
                        assert_eq!(hi, a_hi.max(b_hi));
                    }
                }
            }
        }
    }

    #[test]
    fn record_widens_in_place() {
        let mut map = [RANGE_EMPTY; 4];

        range_map_record(&mut map, 1, 8); // bucket 5
        assert_eq!(unpack_range(map[1]), Some((5, 5)));

        range_map_record(&mut map, 1, 100); // bucket 8
        assert_eq!(unpack_range(map[1]), Some((5, 8)));

        range_map_record(&mut map, 1, 0); // bucket 0
        assert_eq!(unpack_range(map[1]), Some((0, 8)));

        // a value inside the known range changes nothing
        let before = map[1];
        range_map_record(&mut map, 1, 8);
        assert_eq!(map[1], before);

        // untouched entries stay empty, out-of-bounds is ignored
        assert_eq!(map[0], RANGE_EMPTY);
        range_map_record(&mut map, 99, 1);
        assert_eq!(map, [RANGE_EMPTY, before, RANGE_EMPTY, RANGE_EMPTY]);
    }
}
