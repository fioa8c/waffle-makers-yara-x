//! Profiling helpers: bounded top-K min-heap and the `FileTime` data type
//! used to attribute incremental scan time to a labeled input.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::Duration;

/// A single (label, time) pair used in offender lists.
///
/// `label` is the value supplied by the caller — for file scans it is the
/// path as a string; for memory scans it is whatever was passed to
/// [`crate::ScanOptions::label`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTime {
    /// Label identifying the scanned input.
    pub label: String,
    /// Time spent on this single scan.
    pub time: Duration,
}

/// A bounded top-K min-heap of `(Duration, String)` pairs, sorted descending
/// by `Duration` when drained.
///
/// Insertions past the capacity evict the smallest entry. Empty heaps do not
/// allocate (matches the underlying `BinaryHeap` behavior).
pub(crate) struct BoundedTopK {
    capacity: usize,
    heap: BinaryHeap<Reverse<(Duration, String)>>,
}

impl BoundedTopK {
    pub fn new(capacity: usize) -> Self {
        Self { capacity, heap: BinaryHeap::new() }
    }

    /// Inserts `(time, label)`. If the heap is at capacity, evicts the
    /// smallest entry when `time` is greater.
    pub fn insert(&mut self, time: Duration, label: String) {
        if self.heap.len() < self.capacity {
            self.heap.push(Reverse((time, label)));
        } else if let Some(Reverse((min_time, _))) = self.heap.peek()
            && time > *min_time
        {
            self.heap.pop();
            self.heap.push(Reverse((time, label)));
        }
    }

    /// Returns a sorted snapshot of the heap contents, descending by `time`.
    /// Does not modify the heap.
    pub fn sorted_snapshot(&self) -> Vec<FileTime> {
        let mut v: Vec<FileTime> = self
            .heap
            .iter()
            .map(|Reverse((time, label))| FileTime {
                label: label.clone(),
                time: *time,
            })
            .collect();
        v.sort_by(|a, b| b.time.cmp(&a.time));
        v
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(ms: u64) -> Duration { Duration::from_millis(ms) }

    #[test]
    fn fewer_than_k_returns_all_sorted() {
        let mut h = BoundedTopK::new(5);
        h.insert(d(100), "a".into());
        h.insert(d(300), "b".into());
        h.insert(d(200), "c".into());
        let v = h.sorted_snapshot();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].label, "b");
        assert_eq!(v[1].label, "c");
        assert_eq!(v[2].label, "a");
    }

    #[test]
    fn more_than_k_keeps_largest_k() {
        let mut h = BoundedTopK::new(3);
        for (label, ms) in [("a", 100), ("b", 50), ("c", 400), ("d", 200), ("e", 300)] {
            h.insert(d(ms), label.into());
        }
        let v = h.sorted_snapshot();
        assert_eq!(v.len(), 3);
        let labels: Vec<&str> = v.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(labels, vec!["c", "e", "d"]);
    }

    #[test]
    fn equal_smallest_does_not_evict() {
        let mut h = BoundedTopK::new(2);
        h.insert(d(100), "a".into());
        h.insert(d(100), "b".into());
        h.insert(d(100), "c".into()); // should NOT evict (strictly greater required)
        let v = h.sorted_snapshot();
        let labels: Vec<&str> = v.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(labels.len(), 2);
        assert!(labels.contains(&"a") || labels.contains(&"b"));
        assert!(!labels.contains(&"c"));
    }

    #[test]
    fn snapshot_does_not_mutate() {
        let mut h = BoundedTopK::new(3);
        h.insert(d(100), "a".into());
        h.insert(d(200), "b".into());
        let first = h.sorted_snapshot();
        let second = h.sorted_snapshot();
        assert_eq!(first, second);
    }
}
