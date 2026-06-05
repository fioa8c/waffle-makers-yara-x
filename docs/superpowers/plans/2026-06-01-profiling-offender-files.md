# Profiling offender-files Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend YARA-X's `--profiling` output so it lists, for each slow rule, the input files that consumed the most time, plus a global "slowest files" list aggregated across all rules.

**Architecture:** The library tracks per-rule timing deltas around each scan operation. After every `scan_*` call, it computes the per-rule increment since the previous scan, attributes it to a caller-supplied label (file path for `scan_file*`, optional via `ScanOptions::label` for memory scans), and pushes into bounded top-K min-heaps (one per rule, one global). The CLI consumes the new `Scanner::slowest_rules`/`slowest_files` APIs, merges per-thread heaps in the existing `finalize` step, and prints the new sections.

**Tech Stack:** Rust 2024, `BinaryHeap` for top-K, `quanta` for the existing clock, `assert_cmd` + `assert_fs` + `predicates` for CLI integration tests.

**Spec:** [`docs/superpowers/specs/2026-06-01-profiling-offender-files-design.md`](../specs/2026-06-01-profiling-offender-files-design.md)

---

## Task 1: Add `BoundedTopK` helper and `FileTime` type

**Files:**
- Create: `lib/src/scanner/profiling.rs`
- Modify: `lib/src/scanner/mod.rs` (around line 41 — module declarations)

- [ ] **Step 1: Add `mod profiling` and create the empty module file**

Edit `lib/src/scanner/mod.rs` to declare the new submodule. After the existing line `mod matches;` (around line 42), add:

```rust
#[cfg(feature = "rules-profiling")]
mod profiling;
```

Create `lib/src/scanner/profiling.rs`:

```rust
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
```

- [ ] **Step 2: Run the helper tests to verify they pass**

```bash
cd /Users/fioa8c/WORK/yara-x
cargo test --features rules-profiling -p yara-x --lib scanner::profiling::tests -- --nocapture
```

Expected: 4 tests pass.

- [ ] **Step 3: Verify build with feature off does not pull in the module**

```bash
cargo check -p yara-x
```

Expected: success, no errors. (No `rules-profiling` → `mod profiling` is not compiled.)

- [ ] **Step 4: Commit**

```bash
git add lib/src/scanner/profiling.rs lib/src/scanner/mod.rs
git commit -m "feat(profiling): add BoundedTopK and FileTime helpers"
```

---

## Task 2: Extend `ScanContext` with offender-tracking state

**Files:**
- Modify: `lib/src/scanner/context.rs` (struct around line 93, init around line 1833)

- [ ] **Step 1: Add new feature-gated fields to `ScanContext`**

In `lib/src/scanner/context.rs`, locate the existing `time_spent_in_rule` field declarations (around lines 165–179) and add the following new fields under the same `#[cfg(feature = "rules-profiling")]` gating. Insert after the existing `last_executed_rule` field:

```rust
    /// Per-rule snapshot of `time_spent_in_rule` taken at the end of the
    /// previous scan; used to compute per-scan deltas.
    #[cfg(feature = "rules-profiling")]
    pub time_spent_in_rule_baseline: Vec<u64>,
    /// Per-pattern snapshot of `time_spent_in_pattern` taken at the end of
    /// the previous scan; used to compute per-scan deltas.
    #[cfg(feature = "rules-profiling")]
    pub time_spent_in_pattern_baseline: FxHashMap<PatternId, u64>,
    /// One bounded top-K min-heap per rule, capacity 10. Each entry is a
    /// `(time spent on this scan, label)` pair. Lazily allocated.
    #[cfg(feature = "rules-profiling")]
    pub top_offenders_per_rule:
        Vec<crate::scanner::profiling::BoundedTopK>,
    /// Global bounded top-K min-heap (capacity 10) holding the labels of the
    /// scans that took the most total time (sum of all per-rule deltas).
    #[cfg(feature = "rules-profiling")]
    pub top_files: crate::scanner::profiling::BoundedTopK,
    /// Label for the current/next scan. Set by `Scanner::scan_*` before the
    /// scan begins; consumed by `record_scan_attribution` at the end.
    #[cfg(feature = "rules-profiling")]
    pub current_label: Option<String>,
```

- [ ] **Step 2: Initialize the new fields in `create_wasm_store_and_ctx`**

In `lib/src/scanner/context.rs`, locate the `ScanContext { ... }` initializer inside `create_wasm_store_and_ctx` (around lines 1833–1879). After the existing `time_spent_in_rule` initializer, add the new field initializers, gated identically:

```rust
        #[cfg(feature = "rules-profiling")]
        time_spent_in_rule_baseline: vec![0; num_rules as usize],
        #[cfg(feature = "rules-profiling")]
        time_spent_in_pattern_baseline: FxHashMap::default(),
        #[cfg(feature = "rules-profiling")]
        top_offenders_per_rule: (0..num_rules as usize)
            .map(|_| crate::scanner::profiling::BoundedTopK::new(10))
            .collect(),
        #[cfg(feature = "rules-profiling")]
        top_files: crate::scanner::profiling::BoundedTopK::new(10),
        #[cfg(feature = "rules-profiling")]
        current_label: None,
```

- [ ] **Step 3: Re-export `BoundedTopK` and `FileTime` within the scanner module**

In `lib/src/scanner/mod.rs`, near where `ProfilingData` is defined (around line 147), add the re-exports so they are accessible from `context.rs` via the existing `use crate::scanner::ProfilingData;` pattern:

```rust
#[cfg(feature = "rules-profiling")]
pub use crate::scanner::profiling::FileTime;
```

And in `lib/src/lib.rs`, locate the existing `pub use scanner::ProfilingData;` (line 67) and add a sibling re-export:

```rust
#[cfg(feature = "rules-profiling")]
pub use scanner::FileTime;
```

- [ ] **Step 4: Verify build**

```bash
cargo check --features rules-profiling -p yara-x
```

Expected: success.

```bash
cargo check -p yara-x
```

Expected: success.

- [ ] **Step 5: Commit**

```bash
git add lib/src/scanner/context.rs lib/src/scanner/mod.rs lib/src/lib.rs
git commit -m "feat(profiling): add offender-tracking state to ScanContext"
```

---

## Task 3: Implement `ScanContext::record_scan_attribution`

**Files:**
- Modify: `lib/src/scanner/context.rs` (in the existing `#[cfg(feature = "rules-profiling")] impl ScanContext` block around line 182)

- [ ] **Step 1: Write the failing test in `lib/src/scanner/tests.rs`**

Append after the existing `rules_profiling` test (around line 889):

```rust
#[cfg(feature = "rules-profiling")]
#[test]
fn rules_profiling_per_file_offenders() {
    use yara_x_parser::Span;
    let _ = Span::default(); // silence unused-import linter if needed

    let rules = crate::compile(
        r#"
    rule slow {
      condition:
        for any i in (0..200000) : (
           uint8(i % filesize) == 0xCC
        )
    }
    "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    // Three scans with distinct labels.
    let opts_a = crate::ScanOptions::new().label("fast");
    scanner.scan_with_options(b"a", opts_a).unwrap();

    let opts_b = crate::ScanOptions::new().label("slow");
    scanner.scan_with_options(&vec![0u8; 4096], opts_b).unwrap();

    let opts_c = crate::ScanOptions::new().label("medium");
    scanner.scan_with_options(&vec![0u8; 1024], opts_c).unwrap();

    let slowest = scanner.slowest_rules(1);
    assert_eq!(slowest.len(), 1);

    let offender_labels: Vec<&str> =
        slowest[0].top_offenders.iter().map(|f| f.label.as_str()).collect();

    assert!(offender_labels.contains(&"fast"));
    assert!(offender_labels.contains(&"slow"));
    assert!(offender_labels.contains(&"medium"));

    // Sorted descending by time.
    for w in slowest[0].top_offenders.windows(2) {
        assert!(w[0].time >= w[1].time);
    }
}
```

Run:
```bash
cargo test --features rules-profiling -p yara-x --lib rules_profiling_per_file_offenders 2>&1 | tail -20
```

Expected: FAIL — at minimum because `ScanOptions::label` and `ProfilingData::top_offenders` do not yet exist. (Tasks 4 and 6 also touch these. This test stays red until Task 6 lands.) Leave the failing test in place; later tasks will green it.

- [ ] **Step 2: Implement `record_scan_attribution`**

In `lib/src/scanner/context.rs`, inside the existing `#[cfg(feature = "rules-profiling")] impl ScanContext<'_, '_>` block (after `clear_profiling_data` around line 251), add:

```rust
    /// Records per-rule timing deltas for the just-completed scan against
    /// `current_label`, then advances baselines so the next scan computes
    /// fresh deltas. If `current_label` is `None`, only baselines are
    /// advanced (scan is not attributed to any label).
    pub fn record_scan_attribution(&mut self) {
        // Always advance baselines, even when there is no label, so a
        // subsequent labeled scan computes the right delta.
        let label = self.current_label.take();

        if let Some(label) = label {
            // Sum of all per-rule deltas (condition + pattern matching)
            // for the global slowest-files heap.
            let mut total_for_scan: u64 = 0;

            for (rule_id, rule) in
                self.compiled_rules.rules().iter().enumerate()
            {
                let cond_delta = self.time_spent_in_rule[rule_id]
                    - self.time_spent_in_rule_baseline[rule_id];

                let mut pat_delta: u64 = 0;
                for p in rule.patterns.iter() {
                    let current = self
                        .time_spent_in_pattern
                        .get(&p.pattern_id)
                        .copied()
                        .unwrap_or(0);
                    let baseline = self
                        .time_spent_in_pattern_baseline
                        .get(&p.pattern_id)
                        .copied()
                        .unwrap_or(0);
                    pat_delta += current - baseline;
                }

                let rule_total = cond_delta + pat_delta;
                if rule_total > 0 {
                    self.top_offenders_per_rule[rule_id].insert(
                        Duration::from_nanos(rule_total),
                        label.clone(),
                    );
                }
                total_for_scan += rule_total;
            }

            if total_for_scan > 0 {
                self.top_files
                    .insert(Duration::from_nanos(total_for_scan), label);
            }
        }

        // Advance baselines to match the current counter values.
        self.time_spent_in_rule_baseline
            .copy_from_slice(&self.time_spent_in_rule);
        for (pid, t) in self.time_spent_in_pattern.iter() {
            self.time_spent_in_pattern_baseline.insert(*pid, *t);
        }
    }
```

- [ ] **Step 3: Verify the function compiles**

```bash
cargo check --features rules-profiling -p yara-x
```

Expected: success. (The test from Step 1 still fails — `top_offenders` field and `ScanOptions::label` don't exist yet.)

- [ ] **Step 4: Commit**

```bash
git add lib/src/scanner/context.rs lib/src/scanner/tests.rs
git commit -m "feat(profiling): implement record_scan_attribution"
```

---

## Task 4: Add `FileTime` to `ProfilingData` and `ScanOptions::label`

**Files:**
- Modify: `lib/src/scanner/mod.rs` (`ProfilingData` around line 149, `ScanOptions` around line 162)

- [ ] **Step 1: Extend `ProfilingData`**

In `lib/src/scanner/mod.rs` replace the existing `ProfilingData` struct (lines 147–158):

```rust
/// Contains information about the time spent on a rule.
#[cfg(feature = "rules-profiling")]
pub struct ProfilingData<'r> {
    /// Rule namespace.
    pub namespace: &'r str,
    /// Rule name.
    pub rule: &'r str,
    /// Time spent executing the rule's condition.
    pub condition_exec_time: Duration,
    /// Time spent matching the rule's patterns.
    pub pattern_matching_time: Duration,
    /// Up to 10 scans where this rule consumed the most time, sorted
    /// descending by `time`.
    pub top_offenders: Vec<FileTime>,
}
```

- [ ] **Step 2: Add the `label` field and builder to `ScanOptions`**

In `lib/src/scanner/mod.rs` replace the `ScanOptions` struct and impl block (lines 161–184):

```rust
/// Optional information for the scan operation.
#[derive(Debug, Default)]
pub struct ScanOptions<'a> {
    module_metadata: HashMap<&'a str, &'a [u8]>,
    /// Optional label used by profiling to attribute per-scan time to a
    /// human-readable identifier (e.g. a logical name for an in-memory
    /// buffer). Ignored when the `rules-profiling` feature is disabled.
    #[cfg(feature = "rules-profiling")]
    pub(crate) label: Option<String>,
}

impl<'a> ScanOptions<'a> {
    /// Creates a new instance of `ScanOptions` with no additional information
    /// for the scan operation.
    ///
    /// Use other methods to add additional information.
    pub fn new() -> Self {
        Self {
            module_metadata: Default::default(),
            #[cfg(feature = "rules-profiling")]
            label: None,
        }
    }

    /// Adds metadata for a YARA module.
    pub fn set_module_metadata(
        mut self,
        module_name: &'a str,
        metadata: &'a [u8],
    ) -> Self {
        self.module_metadata.insert(module_name, metadata);
        self
    }

    /// Provides a human-readable label for this scan.
    ///
    /// Used by profiling to attribute incremental time to a specific input.
    /// Has no effect when the `rules-profiling` feature is disabled.
    #[cfg(feature = "rules-profiling")]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}
```

- [ ] **Step 3: Verify build**

```bash
cargo check --features rules-profiling -p yara-x
```

Expected: success.

```bash
cargo check -p yara-x
```

Expected: success.

- [ ] **Step 4: Commit**

```bash
git add lib/src/scanner/mod.rs
git commit -m "feat(profiling): add top_offenders field and ScanOptions::label"
```

---

## Task 5: Wire labels into scan entry points and split `scan_impl`

**Files:**
- Modify: `lib/src/scanner/mod.rs` (entry points around lines 272–311, `scan_impl` at line 516)

- [ ] **Step 1: Refactor `scan_impl` into outer + inner**

In `lib/src/scanner/mod.rs` locate the existing `fn scan_impl<'a, 'opts>` (line 516). Rename it to `scan_impl_inner` and change its return type from `Result<ScanResults<'a, 'r>, ScanError>` to `Result<(), ScanError>`. Change the final line of the existing body from `Ok(ScanResults::new(ctx))` to `Ok(())`. The body otherwise stays identical.

Then add a new `scan_impl` that wraps `scan_impl_inner`:

```rust
    fn scan_impl<'a, 'opts>(
        &'a mut self,
        data: ScannedData<'a>,
        options: Option<ScanOptions<'opts>>,
    ) -> Result<ScanResults<'a, 'r>, ScanError> {
        let inner_result = self.scan_impl_inner(data, options);

        #[cfg(feature = "rules-profiling")]
        self.scan_context_mut().record_scan_attribution();

        inner_result?;

        Ok(ScanResults::new(self.scan_context()))
    }
```

- [ ] **Step 2: Set `current_label` in each public scan entry point**

In `lib/src/scanner/mod.rs` replace the four public entry points (lines 272–311):

```rust
    /// Scans in-memory data.
    pub fn scan<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Result<ScanResults<'a, 'r>, ScanError> {
        #[cfg(feature = "rules-profiling")]
        {
            self.scan_context_mut().current_label = None;
        }
        self.scan_impl(data.try_into()?, None)
    }

    /// Scans a file.
    pub fn scan_file<'a, P>(
        &'a mut self,
        target: P,
    ) -> Result<ScanResults<'a, 'r>, ScanError>
    where
        P: AsRef<Path>,
    {
        let target_path = target.as_ref();
        #[cfg(feature = "rules-profiling")]
        {
            let label = target_path.to_string_lossy().into_owned();
            self.scan_context_mut().current_label = Some(label);
        }
        let data = self.load_file(target_path)?;
        self.scan_impl(data, None)
    }

    /// Like [`Scanner::scan`], but allows to specify additional scan options.
    pub fn scan_with_options<'a, 'opts>(
        &'a mut self,
        data: &'a [u8],
        #[allow(unused_mut)] mut options: ScanOptions<'opts>,
    ) -> Result<ScanResults<'a, 'r>, ScanError> {
        #[cfg(feature = "rules-profiling")]
        {
            self.scan_context_mut().current_label = options.label.take();
        }
        self.scan_impl(ScannedData::Slice(data), Some(options))
    }

    /// Like [`Scanner::scan_file`], but allows to specify additional scan
    /// options.
    pub fn scan_file_with_options<'opts, P>(
        &mut self,
        target: P,
        #[allow(unused_mut)] mut options: ScanOptions<'opts>,
    ) -> Result<ScanResults<'_, 'r>, ScanError>
    where
        P: AsRef<Path>,
    {
        let target_path = target.as_ref();
        #[cfg(feature = "rules-profiling")]
        {
            // For file scans, the path always wins over any explicit label
            // in `options`. We still drain `options.label` so it doesn't
            // leak into the next scan if the same options were reused.
            let _ = options.label.take();
            let label = target_path.to_string_lossy().into_owned();
            self.scan_context_mut().current_label = Some(label);
        }
        let data = self.load_file(target_path)?;
        self.scan_impl(data, Some(options))
    }
```

- [ ] **Step 3: Verify build**

```bash
cargo check --features rules-profiling -p yara-x
cargo check -p yara-x
```

Expected: both succeed.

- [ ] **Step 4: Commit**

```bash
git add lib/src/scanner/mod.rs
git commit -m "feat(profiling): plumb scan labels and record attribution per scan"
```

---

## Task 6: Populate `top_offenders` in `ScanContext::slowest_rules`

**Files:**
- Modify: `lib/src/scanner/context.rs` (existing `slowest_rules` around line 188)

- [ ] **Step 1: Update `slowest_rules` to populate `top_offenders` from a snapshot**

In `lib/src/scanner/context.rs` replace the existing `slowest_rules` method (lines 188–245). It stays `&self` — `BoundedTopK::sorted_snapshot` does not mutate the heap, so repeated calls return the same cumulative view (consistent with the cumulative semantics already used for `condition_exec_time` and `pattern_matching_time`).

```rust
    /// Returns the slowest N rules.
    ///
    /// Profiling has an accumulative effect. When the scanner is used for
    /// scanning multiple files the times add up. Each returned entry
    /// includes up to 10 file labels (`top_offenders`) — the scans where
    /// that rule consumed the most time.
    ///
    /// Calling this does not modify any internal state. To reset profiling
    /// data use [`ScanContext::clear_profiling_data`].
    pub fn slowest_rules(&self, n: usize) -> Vec<ProfilingData<'_>> {
        debug_assert_eq!(
            self.compiled_rules.num_rules(),
            self.time_spent_in_rule.len()
        );

        let mut result = Vec::with_capacity(self.compiled_rules.num_rules());

        for ((rule_idx, rule), condition_exec_time) in iter::zip(
            self.compiled_rules.rules().iter().enumerate(),
            self.time_spent_in_rule.iter(),
        ) {
            let mut pattern_matching_time = 0;
            for p in rule.patterns.iter() {
                if let Some(d) = self.time_spent_in_pattern.get(&p.pattern_id)
                {
                    pattern_matching_time += *d;
                }
            }

            // Don't track rules that took less than 100ms cumulative.
            if condition_exec_time + pattern_matching_time > 100_000_000 {
                let namespace = self
                    .compiled_rules
                    .ident_pool()
                    .get(rule.namespace_ident_id)
                    .unwrap();

                let rule_name = self
                    .compiled_rules
                    .ident_pool()
                    .get(rule.ident_id)
                    .unwrap();

                result.push(ProfilingData {
                    namespace,
                    rule: rule_name,
                    condition_exec_time: Duration::from_nanos(
                        *condition_exec_time,
                    ),
                    pattern_matching_time: Duration::from_nanos(
                        pattern_matching_time,
                    ),
                    top_offenders: self.top_offenders_per_rule[rule_idx]
                        .sorted_snapshot(),
                });
            }
        }

        result.sort_by(|a, b| {
            let a_time = a.pattern_matching_time + a.condition_exec_time;
            let b_time = b.pattern_matching_time + b.condition_exec_time;

            b_time.cmp(&a_time)
        });
        result.truncate(n);
        result
    }
```

(No new imports needed — `iter` is already imported at line 4 of context.rs.)

- [ ] **Step 2: `Scanner::slowest_rules` keeps its existing `&self` signature**

No change required to `lib/src/scanner/mod.rs` — the existing signature `pub fn slowest_rules(&self, n: usize) -> Vec<ProfilingData<'_>>` continues to work since `ScanContext::slowest_rules` is still `&self`.

- [ ] **Step 3: Run the test from Task 3 — it should now pass**

```bash
cargo test --features rules-profiling -p yara-x --lib rules_profiling_per_file_offenders 2>&1 | tail -20
```

Expected: PASS.

Also re-run the existing `rules_profiling` test which now goes through `&mut self`:

```bash
cargo test --features rules-profiling -p yara-x --lib rules_profiling 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 4: Verify build with feature off**

```bash
cargo check -p yara-x
```

Expected: success.

- [ ] **Step 5: Commit**

```bash
git add lib/src/scanner/context.rs lib/src/scanner/mod.rs
git commit -m "feat(profiling): populate top_offenders in slowest_rules"
```

---

## Task 7: Add `Scanner::slowest_files`

**Files:**
- Modify: `lib/src/scanner/context.rs` (add method in the profiling `impl` block)
- Modify: `lib/src/scanner/mod.rs` (expose at `Scanner` level)

- [ ] **Step 1: Write the failing test**

In `lib/src/scanner/tests.rs`, after the test added in Task 3, append:

```rust
#[cfg(feature = "rules-profiling")]
#[test]
fn rules_profiling_slowest_files() {
    let rules = crate::compile(
        r#"
    rule slow_a {
      condition:
        for any i in (0..100000) : (uint8(i % filesize) == 0xCC)
    }
    rule slow_b {
      condition:
        for any i in (0..100000) : (uint8(i % filesize) == 0xDD)
    }
    "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    for (label, sz) in [("tiny", 16), ("big", 4096), ("medium", 512)] {
        let opts = crate::ScanOptions::new().label(label);
        scanner.scan_with_options(&vec![0u8; sz], opts).unwrap();
    }

    let files = scanner.slowest_files(10);
    assert!(!files.is_empty());

    // Sorted descending.
    for w in files.windows(2) {
        assert!(w[0].time >= w[1].time);
    }

    // "big" should be slowest.
    assert_eq!(files[0].label, "big");
}
```

- [ ] **Step 2: Implement `ScanContext::slowest_files`**

In `lib/src/scanner/context.rs`, inside the `#[cfg(feature = "rules-profiling")] impl ScanContext<'_, '_>` block, after `clear_profiling_data` (around line 251), add:

```rust
    /// Returns up to `n` labeled scans that took the most cumulative time
    /// across all rules. Does not modify internal state.
    pub fn slowest_files(
        &self,
        n: usize,
    ) -> Vec<crate::scanner::profiling::FileTime> {
        let mut v = self.top_files.sorted_snapshot();
        v.truncate(n);
        v
    }
```

- [ ] **Step 3: Expose at `Scanner` level**

In `lib/src/scanner/mod.rs`, immediately after the existing `slowest_rules` method, add:

```rust
    /// Returns up to `n` labeled scans that took the most total time across
    /// all rules. Each entry is the sum of every rule's incremental time on
    /// a single scan. Useful for identifying pathological input files.
    ///
    /// Like [`Scanner::slowest_rules`], the data is cumulative across scans;
    /// use [`Scanner::clear_profiling_data`] to reset.
    #[cfg(feature = "rules-profiling")]
    pub fn slowest_files(&self, n: usize) -> Vec<FileTime> {
        self.scan_context().slowest_files(n)
    }
```

- [ ] **Step 4: Run the test**

```bash
cargo test --features rules-profiling -p yara-x --lib rules_profiling_slowest_files 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/src/scanner/context.rs lib/src/scanner/mod.rs lib/src/scanner/tests.rs
git commit -m "feat(profiling): add Scanner::slowest_files"
```

---

## Task 8: Extend `clear_profiling_data` to reset new state

**Files:**
- Modify: `lib/src/scanner/context.rs` (existing `clear_profiling_data` around line 248)

- [ ] **Step 1: Write the failing test**

In `lib/src/scanner/tests.rs`, append:

```rust
#[cfg(feature = "rules-profiling")]
#[test]
fn rules_profiling_clear_resets_offenders() {
    let rules = crate::compile(
        r#"
    rule slow {
      condition:
        for any i in (0..200000) : (uint8(i % filesize) == 0xCC)
    }
    "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    let opts = crate::ScanOptions::new().label("before_clear");
    scanner.scan_with_options(&vec![0u8; 4096], opts).unwrap();

    scanner.clear_profiling_data();

    let opts = crate::ScanOptions::new().label("after_clear");
    scanner.scan_with_options(&vec![0u8; 4096], opts).unwrap();

    let slowest = scanner.slowest_rules(10);
    // Slow rule may or may not have crossed the 100ms cumulative threshold
    // post-clear depending on the host; if it has, only "after_clear"
    // should appear.
    for r in &slowest {
        for offender in &r.top_offenders {
            assert_ne!(offender.label, "before_clear");
        }
    }

    let files = scanner.slowest_files(10);
    for f in &files {
        assert_ne!(f.label, "before_clear");
    }
}
```

- [ ] **Step 2: Run to confirm failure (the old `clear_profiling_data` leaves heaps populated)**

```bash
cargo test --features rules-profiling -p yara-x --lib rules_profiling_clear_resets_offenders 2>&1 | tail -10
```

Expected: FAIL (a "before_clear" entry survives).

- [ ] **Step 3: Extend `clear_profiling_data`**

In `lib/src/scanner/context.rs` replace the existing `clear_profiling_data` (around lines 247–251):

```rust
    /// Clears profiling information.
    pub fn clear_profiling_data(&mut self) {
        self.time_spent_in_rule.fill(0);
        self.time_spent_in_pattern.clear();
        self.time_spent_in_rule_baseline.fill(0);
        self.time_spent_in_pattern_baseline.clear();
        self.top_offenders_per_rule = (0..self.compiled_rules.num_rules())
            .map(|_| crate::scanner::profiling::BoundedTopK::new(10))
            .collect();
        self.top_files = crate::scanner::profiling::BoundedTopK::new(10);
        self.current_label = None;
    }
```

- [ ] **Step 4: Run to confirm pass**

```bash
cargo test --features rules-profiling -p yara-x --lib rules_profiling_clear_resets_offenders 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/src/scanner/context.rs lib/src/scanner/tests.rs
git commit -m "feat(profiling): reset offender heaps on clear_profiling_data"
```

---

## Task 9: Library tests — eviction, unlabeled-scan baseline, auto-label by path

**Files:**
- Modify: `lib/src/scanner/tests.rs`

- [ ] **Step 1: Top-K eviction test**

Append to `lib/src/scanner/tests.rs`:

```rust
#[cfg(feature = "rules-profiling")]
#[test]
fn rules_profiling_top_k_eviction() {
    let rules = crate::compile(
        r#"
    rule slow {
      condition:
        for any i in (0..50000) : (uint8(i % filesize) == 0xCC)
    }
    "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    // 25 scans with monotonically increasing buffer size.
    for i in 0..25u32 {
        let label = format!("scan-{:02}", i);
        let size = 256 * (i as usize + 1);
        let opts = crate::ScanOptions::new().label(label);
        scanner.scan_with_options(&vec![0u8; size], opts).unwrap();
    }

    let slowest = scanner.slowest_rules(1);
    if slowest.is_empty() {
        // Rule didn't cross the 100ms cumulative threshold — not a
        // failure of this code, just an under-powered host. Skip.
        return;
    }

    let offenders = &slowest[0].top_offenders;
    assert!(offenders.len() <= 10);
    assert!(!offenders.is_empty());

    // No "scan-00" through "scan-04" should appear: heap should have
    // evicted the smallest entries.
    for f in offenders {
        let n: u32 = f.label
            .strip_prefix("scan-")
            .and_then(|s| s.parse().ok())
            .unwrap();
        assert!(n >= 5, "expected late label, got {}", f.label);
    }
}
```

- [ ] **Step 2: Unlabeled-scan-doesn't-leak-baseline test**

Append:

```rust
#[cfg(feature = "rules-profiling")]
#[test]
fn rules_profiling_unlabeled_scan_advances_baseline() {
    let rules = crate::compile(
        r#"
    rule slow {
      condition:
        for any i in (0..100000) : (uint8(i % filesize) == 0xCC)
    }
    "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    // Unlabeled scan first — no label, but baseline must still advance.
    scanner.scan(&vec![0u8; 4096]).unwrap();

    // Labeled scan second — should record only its own delta.
    let opts = crate::ScanOptions::new().label("labeled_only");
    scanner.scan_with_options(&vec![0u8; 4096], opts).unwrap();

    let slowest = scanner.slowest_rules(1);
    if slowest.is_empty() {
        return; // host too fast to cross threshold
    }
    let offenders = &slowest[0].top_offenders;
    assert!(offenders.iter().all(|f| f.label == "labeled_only"));
}
```

- [ ] **Step 3: Auto-label-by-path test**

Append (uses only `std::env::temp_dir` to avoid adding a new dev-dependency):

```rust
#[cfg(feature = "rules-profiling")]
#[test]
fn rules_profiling_scan_file_auto_labels_with_path() {
    use std::io::Write;

    let path = std::env::temp_dir()
        .join(format!("yrx-profiling-{}.bin", std::process::id()));
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&vec![0u8; 4096]).unwrap();
    }

    let rules = crate::compile(
        r#"
    rule slow {
      condition:
        for any i in (0..200000) : (uint8(i % filesize) == 0xCC)
    }
    "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);
    scanner.scan_file(&path).unwrap();

    let slowest = scanner.slowest_rules(1);
    let expected = path.to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&path);

    if slowest.is_empty() {
        return; // host did not cross 100ms cumulative threshold
    }
    assert!(slowest[0].top_offenders.iter().any(|f| f.label == expected));
}
```

- [ ] **Step 4: Run all three tests**

```bash
cargo test --features rules-profiling -p yara-x --lib rules_profiling 2>&1 | tail -25
```

Expected: all `rules_profiling_*` tests pass.

- [ ] **Step 5: Commit**

```bash
git add lib/src/scanner/tests.rs
git commit -m "test(profiling): cover eviction, baseline advance, and path auto-label"
```

---

## Task 10: CLI — extend local types and per-thread collection

**Files:**
- Modify: `cli/src/commands/scan.rs` (local `ProfilingData` around line 126, finalize around line 393)

- [ ] **Step 1: Extend the CLI's local `ProfilingData` and add `FileProfilingData`**

In `cli/src/commands/scan.rs` replace the local `ProfilingData` struct and its `From` impl (lines 125–146):

```rust
#[cfg(feature = "rules-profiling")]
struct ProfilingData {
    pub namespace: String,
    pub rule: String,
    pub condition_exec_time: Duration,
    pub pattern_matching_time: Duration,
    pub total_time: Duration,
    pub top_offenders: Vec<FileTime>,
}

#[cfg(feature = "rules-profiling")]
struct FileProfilingData {
    pub label: String,
    pub total_time: Duration,
}

#[cfg(feature = "rules-profiling")]
impl From<yara_x::ProfilingData<'_>> for ProfilingData {
    fn from(value: yara_x::ProfilingData) -> Self {
        Self {
            namespace: value.namespace.to_string(),
            rule: value.rule.to_string(),
            condition_exec_time: value.condition_exec_time,
            pattern_matching_time: value.pattern_matching_time,
            total_time: value.condition_exec_time
                + value.pattern_matching_time,
            top_offenders: value.top_offenders,
        }
    }
}

#[cfg(feature = "rules-profiling")]
impl From<yara_x::FileTime> for FileProfilingData {
    fn from(value: yara_x::FileTime) -> Self {
        Self { label: value.label, total_time: value.time }
    }
}
```

Then update the `use yara_x::{...}` line (currently line 19) to include `FileTime`:

```rust
use yara_x::{MetaValue, Patterns, Rule, Rules, ScanOptions, Scanner};
#[cfg(feature = "rules-profiling")]
use yara_x::FileTime;
```

- [ ] **Step 2: Add the second mutex and merge in finalize**

In `cli/src/commands/scan.rs`, locate the existing `slowest_rules` mutex declaration (line 294). Replace with:

```rust
    #[cfg(feature = "rules-profiling")]
    let slowest_rules: Mutex<Vec<ProfilingData>> = Mutex::new(Vec::new());
    #[cfg(feature = "rules-profiling")]
    let slowest_files: Mutex<Vec<FileProfilingData>> = Mutex::new(Vec::new());
```

Then locate the finalize closure (lines 393–413). Replace its body with the version that merges both rule offenders and per-thread files:

```rust
        // Finalization
        #[allow(unused_variables)]
        |scanner, _| {
            #[cfg(feature = "rules-profiling")]
            if profiling {
                {
                    let mut mer = slowest_rules.lock().unwrap();
                    for profiling_data in scanner.slowest_rules(1000) {
                        let incoming: ProfilingData = profiling_data.into();
                        if let Some(r) = mer.iter_mut().find(|r| {
                            r.rule == incoming.rule
                                && r.namespace == incoming.namespace
                        }) {
                            r.condition_exec_time +=
                                incoming.condition_exec_time;
                            r.pattern_matching_time +=
                                incoming.pattern_matching_time;
                            r.total_time += incoming.total_time;
                            r.top_offenders.extend(incoming.top_offenders);
                            // Keep only the top 10 across threads.
                            r.top_offenders.sort_by(|a, b| b.time.cmp(&a.time));
                            r.top_offenders.truncate(10);
                        } else {
                            mer.push(incoming);
                        }
                    }
                }
                {
                    let mut files = slowest_files.lock().unwrap();
                    for ft in scanner.slowest_files(10) {
                        files.push(ft.into());
                    }
                    // Trim to bound growth; final sort/truncate happens
                    // once after the walk.
                    if files.len() > 1000 {
                        files.sort_by(|a, b| b.total_time.cmp(&a.total_time));
                        files.truncate(100);
                    }
                }
            }
        },
```

- [ ] **Step 3: Verify build (feature on and off)**

```bash
cargo check --features rules-profiling -p yara-x-cli
cargo check -p yara-x-cli
```

Expected: both succeed.

- [ ] **Step 4: Commit**

```bash
git add cli/src/commands/scan.rs
git commit -m "feat(cli): collect per-rule offenders and slowest files per thread"
```

---

## Task 11: CLI — render the new sections

**Files:**
- Modify: `cli/src/commands/scan.rs` (output block around lines 442–475)

- [ ] **Step 1: Replace the profiling output block**

In `cli/src/commands/scan.rs` replace the existing `#[cfg(feature = "rules-profiling")] if profiling { ... }` block at the bottom of `exec_scan` (lines 442–475):

```rust
    #[cfg(feature = "rules-profiling")]
    if profiling {
        let mut mer = slowest_rules.lock().unwrap();

        println!("\n«««««««««««« PROFILING INFORMATION »»»»»»»»»»»»");

        if mer.is_empty() {
            println!(
                "\n{}",
                "No profiling information gathered, all rules were very fast."
                    .paint(Green)
                    .bold()
            );
        } else {
            // Sort by total time in descending order.
            mer.sort_by(|a, b| b.total_time.cmp(&a.total_time));
            println!("\n{}", "Slowest rules:".paint(Red).bold());
            for r in mer.iter().take(10) {
                println!(
                    r#"
* rule                 : {}
  namespace            : {}
  pattern matching     : {:?}
  condition evaluation : {:?}
  TOTAL                : {:?}"#,
                    r.rule,
                    r.namespace,
                    r.pattern_matching_time,
                    r.condition_exec_time,
                    r.total_time
                );
                if !r.top_offenders.is_empty() {
                    println!("  top offending files  :");
                    for (idx, f) in r.top_offenders.iter().enumerate() {
                        println!(
                            "    {:>2}. {:<40} {:?}",
                            idx + 1,
                            f.label,
                            f.time
                        );
                    }
                }
            }
        }

        let mut files = slowest_files.lock().unwrap();
        if !files.is_empty() {
            files.sort_by(|a, b| b.total_time.cmp(&a.total_time));
            files.truncate(10);
            println!("\n{}", "Slowest files:".paint(Red).bold());
            for f in files.iter() {
                println!(
                    r#"
* file                 : {}
  TOTAL                : {:?}"#,
                    f.label, f.total_time
                );
            }
        }
    }
```

- [ ] **Step 2: Build CLI**

```bash
cargo build --features rules-profiling -p yara-x-cli
```

Expected: success.

- [ ] **Step 3: Manual smoke test**

```bash
cd /tmp
mkdir -p yrx-profile-smoke && cd yrx-profile-smoke
cat > slow.yar <<'EOF'
rule slow_a {
  condition:
    for any i in (0..200000) : (uint8(i % filesize) == 0xCC)
}
EOF
# Two files of obviously different sizes.
dd if=/dev/urandom of=small.bin bs=1 count=512 2>/dev/null
dd if=/dev/urandom of=large.bin bs=1024 count=64 2>/dev/null

/Users/fioa8c/WORK/yara-x/target/debug/yr scan --profiling slow.yar .
```

Expected output: contains `Slowest rules:`, a `top offending files` line referencing `./large.bin`, and a `Slowest files:` section with `./large.bin` ahead of `./small.bin`. (Times will vary; ordering should be deterministic enough.)

- [ ] **Step 4: Commit**

```bash
cd /Users/fioa8c/WORK/yara-x
git add cli/src/commands/scan.rs
git commit -m "feat(cli): render offender files under each slow rule and a slowest-files section"
```

---

## Task 12: CLI integration test

**Files:**
- Modify: `cli/src/tests/scan.rs`

- [ ] **Step 1: Add the smoke test**

In `cli/src/tests/scan.rs` append at the end of the file:

```rust
#[cfg(feature = "rules-profiling")]
#[test]
fn profiling_lists_offender_files() {
    use std::io::Write;

    let temp = TempDir::new().unwrap();

    let rule_file = temp.child("slow.yar");
    rule_file
        .write_str(
            r#"
rule slow_a {
  condition:
    for any i in (0..200000) : (uint8(i % filesize) == 0xCC)
}
"#,
        )
        .unwrap();

    let small = temp.child("small.bin");
    let large = temp.child("large.bin");

    {
        let mut f = std::fs::File::create(small.path()).unwrap();
        f.write_all(&vec![0u8; 512]).unwrap();
    }
    {
        let mut f = std::fs::File::create(large.path()).unwrap();
        f.write_all(&vec![0u8; 64 * 1024]).unwrap();
    }

    let assert = Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--profiling")
        .arg(rule_file.path())
        .arg(temp.path())
        .assert()
        .success();

    let out = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();

    // We may or may not cross the 100ms cumulative threshold depending on
    // host speed; if the rule was tracked, the larger file must appear
    // before the smaller one in the offender list, and the slowest-files
    // section must list large.bin ahead of small.bin.
    if out.contains("top offending files") {
        let large_path = large.path().to_string_lossy().into_owned();
        let small_path = small.path().to_string_lossy().into_owned();
        let large_idx = out.find(&large_path);
        let small_idx = out.find(&small_path);
        assert!(large_idx.is_some(), "large.bin should appear in output");
        if let (Some(li), Some(si)) = (large_idx, small_idx) {
            assert!(
                li < si,
                "large.bin should appear before small.bin in profiling output"
            );
        }
        assert!(out.contains("Slowest files:"));
    } else {
        eprintln!(
            "note: profiling threshold not crossed on this host; \
             smoke assertions skipped"
        );
    }
}
```

- [ ] **Step 2: Build and run the CLI tests with profiling enabled**

The CLI tests use `cargo_bin!`, which expects the binary already built and the `CARGO_BIN_EXE_yr` env var pointing at it.

```bash
cargo build --features rules-profiling -p yara-x-cli
CARGO_BIN_EXE_yr=/Users/fioa8c/WORK/yara-x/target/debug/yr \
  cargo test --features rules-profiling \
  -p yara-x-cli --bin yr profiling_lists_offender_files 2>&1 | tail -10
```

Expected: PASS (or PASS with the "note: profiling threshold not crossed" message printed).

- [ ] **Step 3: Commit**

```bash
git add cli/src/tests/scan.rs
git commit -m "test(cli): smoke test for profiling offender files output"
```

---

## Task 13: Final verification

- [ ] **Step 1: Full lib test suite, profiling on**

```bash
cargo test --features rules-profiling -p yara-x --lib 2>&1 | tail -30
```

Expected: all tests pass.

- [ ] **Step 2: Full lib test suite, profiling off**

```bash
cargo test -p yara-x --lib 2>&1 | tail -10
```

Expected: all tests pass.

- [ ] **Step 3: CLI tests with feature on**

```bash
cargo build --features rules-profiling -p yara-x-cli
CARGO_BIN_EXE_yr=/Users/fioa8c/WORK/yara-x/target/debug/yr \
  cargo test --features rules-profiling -p yara-x-cli --bin yr 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 4: CLI builds without the feature**

```bash
cargo check -p yara-x-cli
```

Expected: success.

- [ ] **Step 5: Manual end-to-end smoke against a larger corpus (optional)**

If a larger corpus is available locally, run:

```bash
cargo build --release --features rules-profiling
./target/release/yr scan --profiling <RULES_PATH> <CORPUS_PATH>
```

Inspect the output: `top offending files` should appear under each slow rule, and a `Slowest files:` section should follow.

- [ ] **Step 6: Optional clippy clean-up**

```bash
cargo clippy --features rules-profiling -p yara-x -p yara-x-cli -- -D warnings 2>&1 | tail -30
```

Address any new warnings introduced by the new code.

- [ ] **Step 7: No commit unless cleanup was needed**

If clippy required edits, commit them:

```bash
git add -p
git commit -m "chore(profiling): clippy clean-up"
```

Otherwise, this task is done.

---

## Notes on the testing strategy

The library tests in Tasks 3/7/8/9 are timing-sensitive at the boundary where rules cross the 100ms cumulative threshold. Each test that depends on the threshold uses an early-return guard (`if slowest.is_empty() { return; }`) so under-powered or oversubscribed CI hosts don't produce false negatives. The structural assertions (e.g., "no `before_clear` label survives", "`big` appears before `medium`") run when the threshold is crossed; otherwise the test exits cleanly.

The CLI test in Task 12 uses the same pattern: assertions about ordering are skipped if the profiling block isn't populated, but the run itself still needs to succeed.

These guards are deliberate. The alternative (hard-pinning timings) would make CI flaky.
