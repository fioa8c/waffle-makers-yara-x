# Profiling: report the file offenders behind slow rules

Status: draft (awaiting implementation plan)
Author: Fioravante Souza
Date: 2026-06-01

## Problem

`yr scan --profiling` (lib feature `rules-profiling`) currently reports the
cumulative time spent by each rule across the entire scan, but does not
attribute that time to specific input files. On a 5M-file scan, knowing
that `php_backdoor_nopriv_001` spent 8.7s in total is useful, but the user
cannot tell *which files* in the input set made the rule slow — the actual
debugging artefact (the pathological input) is invisible.

Example output today:

```
«««««««««««« PROFILING INFORMATION »»»»»»»»»»»»

Slowest rules:

* rule                 : php_backdoor_nopriv_001
  namespace            : default
  pattern matching     : 7.849100169s
  condition evaluation : 898.425633ms
  TOTAL                : 8.747525802s
```

## Goal

Extend the profiling output so it lists, for each slow rule, the input files
that contributed the most to that rule's total time, and also surfaces a
global "slowest files" list aggregated across all rules.

## Non-goals

- Python / C-API surface changes for the new `top_offenders` field (can come later).
- Wiring profiling info into `--output-format=json|ndjson` (still text-only).
- A user-facing flag to configure top-K (K is hardcoded to 10).
- Per-pattern (rather than per-rule) offender drilldown.

## Approach (selected)

Track per-rule and global top-K offenders inside the library, using
*delta snapshots* around each scan operation. The CLI consumes the new API,
merges per-thread heaps at finalize, and prints the extra sections.

Alternative considered and rejected:

- **CLI-side delta tracking** (call `slowest_rules()` before and after every
  file, diff client-side): would either require exposing the raw per-rule
  counters (effectively the same library change) or be blind to small
  per-file contributions due to the existing 100ms cumulative filter on
  `slowest_rules()`. Defeats the purpose.

## Architecture and data flow

All additions are under `#[cfg(feature = "rules-profiling")]`.

New state added to `ScanContext` (in `lib/src/scanner/context.rs`):

- `time_spent_in_rule_baseline: Vec<u64>` — counter snapshot taken before
  each scan; used to compute per-rule incremental time.
- `time_spent_in_pattern_baseline: FxHashMap<PatternId, u64>` — same for
  patterns.
- `top_offenders_per_rule: Vec<BoundedTopK<String>>` — one bounded min-heap
  per rule (capacity 10), holds `(Duration, label)`.
- `top_files: BoundedTopK<String>` — single bounded min-heap (capacity 10)
  for the global slowest-files list. Each entry's `Duration` is the sum of
  all per-rule deltas for that scan.
- `current_label: Option<String>` — set by `Scanner` before delegating into
  the wasm scan loop, cleared after.

Lifecycle of a single scan call:

1. `Scanner::scan_*` sets `current_label` from caller input.
2. Wasm scan runs, mutating `time_spent_in_rule[]` and
   `time_spent_in_pattern{}` as today.
3. On the way out, `Scanner` invokes
   `ScanContext::record_scan_attribution()`:
   - If `current_label` is `Some(label)`: compute
     `delta[rule] = current - baseline` for each rule, compute
     `pattern_delta` summed over that rule's patterns, push
     `(rule_delta + pattern_delta, label.clone())` into the rule's heap,
     and push the sum across all rules into `top_files`.
   - Whether labeled or not, copy `time_spent_in_rule` into the baseline
     and update the pattern map baseline for the keys touched this scan.

Threading: each `Scanner` owns its own `ScanContext`, so heaps are
scanner-local and lock-free on the hot path. The CLI already aggregates
per-thread `slowest_rules()` results under a mutex in `finalize`; the same
mutex covers the new offender lists.

`BoundedTopK<T>` is a small new helper in a new file
`lib/src/scanner/profiling.rs`, implemented with
`std::collections::BinaryHeap<Reverse<(Duration, T)>>` capped at K. ~30 LOC.

## Library API changes

### Extended `ProfilingData<'r>` (in `lib/src/scanner/mod.rs`)

```rust
pub struct ProfilingData<'r> {
    pub namespace: &'r str,
    pub rule: &'r str,
    pub condition_exec_time: Duration,
    pub pattern_matching_time: Duration,
    /// Up to 10 scans where this rule consumed the most time, sorted
    /// descending by `time`.
    pub top_offenders: Vec<FileTime>,
}

pub struct FileTime {
    /// Caller-supplied label. For `scan_file*` this is the file path as a
    /// `String`. For `scan_mem*` it is the value passed to
    /// `ScanOptions::label`, or absent (scan not tracked).
    pub label: String,
    /// Sum of condition + pattern-matching time the rule spent on that
    /// single scan.
    pub time: Duration,
}
```

### New `Scanner` method

```rust
/// Returns up to `n` labeled scans that took the most cumulative time
/// across all rules. Each entry is the sum of every rule's incremental
/// time on that single scan.
pub fn slowest_files(&self, n: usize) -> Vec<FileTime>;
```

### Labeling the input

| Method | Label source |
|---|---|
| `scan_file(path)` / `scan_file_with_options(path, opts)` | `path.to_string_lossy().into_owned()` (automatic) |
| `scan_mem(buf)` / `scan_mem_with_options(buf, opts)` | `None` by default; opt in via `ScanOptions::label` |

New builder on `ScanOptions`:

```rust
impl<'a> ScanOptions<'a> {
    /// Provides a human-readable label for this scan. Used by profiling to
    /// attribute incremental time to a specific input.
    pub fn label(mut self, label: impl Into<String>) -> Self { ... }
}
```

`ScanOptions::label` lives under `#[cfg(feature = "rules-profiling")]`,
matching the rest of the profiling API. Callers that conditionally enable
the feature need to gate their `.label(...)` calls accordingly.

### Extended `clear_profiling_data()`

Clears: existing counters, both baselines, all per-rule heaps, the global
file heap, and `current_label`.

### Non-breaking

No changes to existing `Scanner::scan_*` signatures, `Rules`, `Compiler`,
FFI/C-API, or language bindings in this slice.

## CLI integration

`cli/src/commands/scan.rs`:

- The local `ProfilingData` struct (the CLI mirror that drops the `'r`
  lifetime) gains a `top_offenders: Vec<FileTime>` field.
- A new local `FileProfilingData { label: String, total_time: Duration }`
  struct is introduced for the global slowest-files list.
- A second `Mutex<Vec<FileProfilingData>>` collects per-thread
  `slowest_files()` results next to the existing `slowest_rules` mutex.

Per-thread finalize merges each scanner's `top_offenders` into the matching
rule entry (concat then sort-truncate to 10) and appends
`slowest_files(10)` into the global vec. After the walk the global vec is
sorted descending by `total_time` and truncated to 10.

Merging top-K across threads uses the trivial concat + sort + truncate
strategy — with `N_threads × 10` entries per list this is negligible.

### Text output

```
«««««««««««« PROFILING INFORMATION »»»»»»»»»»»»

Slowest rules:

* rule                 : php_backdoor_nopriv_001
  namespace            : default
  pattern matching     : 7.849100169s
  condition evaluation : 898.425633ms
  TOTAL                : 8.747525802s
  top offending files  :
    1. /scan/pool/uploads/abc.php                  3.214s
    2. /scan/pool/uploads/xyz.phtml                1.892s
    3. /scan/pool/legacy/old-shell.php             0.954s
    ...

Slowest files:

* file                 : /scan/pool/uploads/abc.php
  TOTAL                : 5.214s

* file                 : /scan/pool/uploads/xyz.phtml
  TOTAL                : 4.892s
...
```

- Paths are printed verbatim — no truncation, no relativization.
- If a rule's `top_offenders` is empty, the `top offending files` line is
  omitted.
- If the global slowest-files list is empty, the `Slowest files:` section
  header is omitted too.
- JSON / NDJSON output is unchanged — the profiling block is text-only
  today and stays text-only.

## Edge cases

- **Threshold.** No threshold is applied to per-scan attribution; the
  bounded top-K heap handles selection. The existing 100ms cumulative
  filter on `slowest_rules()` is unchanged — a rule's offender list is
  only ever *displayed* if the rule itself clears that bar.
- **Scan errors / timeouts.** Attribution is recorded regardless of
  scan outcome: any partial time spent on a file is attributed to it.
  A file that timed out *is* an offender.
- **Same label scanned twice.** Allowed; both entries land independently.
  Caller-side dedup if needed.
- **Empty label string.** Treated as a valid label; appears blank in
  output.
- **Concurrent scanners.** Each `Scanner` is independent. Merging happens
  at CLI finalize under the existing mutex.
- **Profiling feature off.** All new state, methods, and
  `ScanOptions::label` are `cfg`-gated; no overhead when the feature is
  disabled.
- **Memory.** Per-scanner worst case: `num_rules × 10 × sizeof(FileTime)`
  for the rule heaps, but heaps only grow as scans happen. Labels are
  owned `String`s; net resident size after merge is on the order of ~100
  strings.

## Testing

Unit tests in `lib/src/scanner/tests.rs` (under
`#[cfg(feature = "rules-profiling")]`):

1. **Single rule, multiple labeled scans.** Three `scan_mem_with_options`
   calls with labels `"fast"`, `"slow"`, `"medium"`. Assert
   `slowest_rules(1)[0].top_offenders` contains all three labels in
   time-descending order.
2. **Top-K eviction.** 25 labeled scans with monotonically increasing
   buffer size; assert `top_offenders.len() == 10` and that it contains
   the 10 slowest (latest) labels.
3. **`slowest_files()` aggregation.** Two rules, three labeled scans;
   assert returned entries' `time` equals the sum of both rules' deltas
   on that scan and are ordered descending.
4. **Unlabeled scan doesn't corrupt baselines.** Interleave labeled and
   unlabeled scans; assert labeled-scan offenders show only their own
   deltas.
5. **`clear_profiling_data()` resets everything.** Scan with labels,
   clear, scan again, assert only post-clear labels appear.
6. **`scan_file_with_options` auto-labels with path.** Write a temp file,
   scan it, assert the file's path appears in `top_offenders`.

Unit tests for `BoundedTopK` in `lib/src/scanner/profiling.rs`:

- Inserting fewer than K returns all in sorted order.
- Inserting more than K keeps the largest K.
- Iteration order is descending by time.

CLI integration test in `cli/tests/`:

- Temp directory with two files of very different sizes, a rule that takes
  nontrivial time. Run `yr scan --profiling`. Assert the larger file's
  path appears before the smaller one in the offender list. Assertion is
  lenient (ordering only — absolute times are environment-dependent).

Documentation:

- Doc comments updated on `ProfilingData`, `Scanner::slowest_rules`,
  `Scanner::slowest_files`, `Scanner::clear_profiling_data`,
  `ScanOptions::label`.
- If a profiling section exists under `site/content/docs/`, add a brief
  note about the offender list. (To be checked during implementation;
  otherwise skipped.)

Benchmarks: not gating. If a scanner bench already exists in
`lib/benches/`, a smoke check confirms per-scan overhead of
`record_scan_attribution()` is sub-microsecond. No new bench infrastructure
is added for this slice.

## Risks

- **Hot-path overhead.** `record_scan_attribution()` runs once per scan
  call. Cost: one pass over `time_spent_in_rule` (`num_rules` u64 reads
  + subtraction), a pass over the rule's pattern set, and up to one heap
  insert per rule with a non-zero delta. On large rulesets this is more
  expensive than the current code, but still negligible relative to scan
  time itself. Mitigated by only running when the feature is enabled.
- **Memory growth on enormous rulesets.** The `top_offenders_per_rule`
  vector is `num_rules` long even if most rules never see any time.
  Empty heaps are cheap (`BinaryHeap` doesn't allocate until first push),
  so practical cost is `num_rules × sizeof(BoundedTopK)` ≈ a few dozen
  bytes per rule. Acceptable.
- **Label allocation churn.** Each labeled scan allocates a `String`. On
  the 5M-file CLI use case this is one allocation per file, dwarfed by
  scan cost. Acceptable.
