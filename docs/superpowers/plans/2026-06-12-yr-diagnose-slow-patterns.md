# `yr diagnose` Slow-Pattern Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new `yr diagnose` subcommand that explains, per slow pattern, which heuristic flagged it, the extracted atoms, the offending sub-expression, and a fix suggestion — with an optional `--scan` mode for real per-rule timing.

**Architecture:** The `Compiler` (lib crate) gains an opt-in diagnostics-collection mode that records one structured `PatternDiagnostics` entry per compiled regexp/hex pattern segment, built from the same extracted atoms the scanner uses. A HIR walker derives "culprit" findings. The CLI subcommand compiles with collection on and renders the report (text/JSON); suggestion strings live in the CLI, facts live in the lib.

**Tech Stack:** Rust workspace. Lib crate `yara-x` (`lib/`), CLI crate (`cli/`, binary `yr`, uses clap builder API). Tests: `cargo test`, CLI integration tests with `assert_cmd`/`assert_fs`/`predicates`.

**Branch:** `feature/yr-diagnose-slow-patterns` (already created).

**Spec:** `docs/superpowers/specs/2026-06-12-slow-pattern-diagnostics-design.md`

---

## Background for the implementer (read first)

- The slow-pattern verdict happens in `Compiler::c_regexp()` at `lib/src/compiler/mod.rs:2514-2606`. It runs `minmax()` over atom lengths of `re_atoms: Vec<re::RegexpAtom>` and raises `warnings::SlowPattern` (or an error if `error_on_slow_pattern`).
- A **second** SlowPattern site exists at `lib/src/compiler/mod.rs:1596-1623`: patterns that are repetitions of a common byte (`{ 00 00 00 00 }`, `"\x90\x90\x90\x90\x90"`). This one can fire for Text patterns too.
- `c_regexp()` is called (possibly multiple times per pattern, for chained/segmented hex patterns with large gaps) from `c_regexp_pattern()`. By that time the current rule has already been pushed: `self.rules.last()` is the rule being compiled; resolve its name via `self.ident_pool.get(rule_info.ident_id)` (returns `Option<&str>`).
- The pattern identifier (e.g. `$a`) is only available in the loop at `lib/src/compiler/mod.rs:1818-1862` (`pattern.identifier().name`), before `pattern.into_pattern()` consumes it.
- Patterns are deduplicated across rules (mod.rs:1755-1768): a pattern shared by several rules is compiled (and recorded) only once, attributed to the first rule. Same behavior as today's warning. Don't fight this.
- `Atom` (in `lib/src/compiler/atoms/mod.rs`) has `len()`, `is_exact()`, and `impl AsRef<[u8]>` (line 117). `DESIRED_ATOM_SIZE = 4` is `pub(crate)` (line 80).
- `re::hir::Hir` (`lib/src/re/hir.rs`) wraps `regex_syntax::hir::Hir` in field `inner` which is `pub(super)` — Task 4 adds a `pub(crate)` accessor.
- `Span` is `yara_x_parser::Span(pub Range<u32>)` — public tuple struct over byte offsets. Already imported in compiler/mod.rs (line 30).
- Module declarations in `lib/src/compiler/mod.rs` are at lines 70-84 (`pub mod warnings;` etc.). Public re-export modules in `lib/src/lib.rs` are at ~95-117 (`pub mod warnings { ... }` pattern).
- CLI subcommands: defined in `cli/src/commands/<name>.rs`, registered in `cli/src/commands/mod.rs` (mod decl + `pub use` + `subcommands(vec![...])`) and dispatched in `cli/src/main.rs` match. Model `diagnose` on `cli/src/commands/compile.rs`. Shared helpers `compilation_args()`, `create_compiler()`, `get_external_vars()`, `path_with_namespace_parser` live in `cli/src/commands/mod.rs`.
- CLI integration tests live in `cli/src/tests/<name>.rs`, registered in `cli/src/tests/mod.rs`, using `Command::new(cargo_bin!("yr"))`.
- Build/test commands (run from repo root): `cargo build -p yara-x-cli`, `cargo test -p yara-x`, `cargo test -p yara-x-cli`. Format with `cargo fmt --all` before each commit.

---

### Task 1: Diagnostics data types and the `SlowReason` heuristic (TDD)

**Files:**
- Create: `lib/src/compiler/diagnostics/mod.rs`
- Modify: `lib/src/compiler/mod.rs:80-84` (module declaration)

- [ ] **Step 1: Create the module with types and a failing-to-compile test**

Create `lib/src/compiler/diagnostics/mod.rs`:

```rust
/*! Structured diagnostics about pattern slowness.

When diagnostics collection is enabled with
[`crate::Compiler::collect_pattern_diagnostics`], the compiler records one
[`PatternDiagnostics`] entry per compiled regexp/hex pattern segment, built
from the same extracted atoms used by the scanner. These records power the
`yr diagnose` command.
*/

use yara_x_parser::Span;

/// Maximum number of sample atoms stored in [`AtomStats::samples`].
pub const MAX_SAMPLE_ATOMS: usize = 8;

/// Diagnostic record for a single compiled pattern (or pattern segment).
///
/// Hex patterns with large gaps (e.g. `{ 01 02 03 [0-2000] 04 05 06 }`) are
/// split into chained segments before compilation; each segment produces its
/// own record with the same `rule_name`/`pattern_ident`/`span`.
#[derive(Clone, Debug)]
pub struct PatternDiagnostics {
    /// Name of the rule the pattern belongs to. Patterns are deduplicated
    /// across rules; a shared pattern is attributed to the first rule that
    /// declared it.
    pub rule_name: String,
    /// Pattern identifier, e.g. `$a`.
    pub pattern_ident: String,
    /// Span of the pattern declaration in the source file.
    pub span: Span,
    /// Why the pattern is slow. `None` means the pattern is not slow.
    pub slow_reason: Option<SlowReason>,
    /// Statistics about the atoms extracted from the pattern. `None` for
    /// records produced by the common-byte-repetition check, which runs
    /// before atom extraction.
    pub atom_stats: Option<AtomStats>,
    /// Sub-expressions identified as the likely cause of slowness.
    /// Best-effort: may be empty even for slow patterns.
    pub culprits: Vec<Culprit>,
}

/// Statistics about the atoms extracted from a pattern.
#[derive(Clone, Debug)]
pub struct AtomStats {
    pub count: usize,
    /// Length of the shortest atom. 0 when `count` is 0.
    pub min_len: usize,
    /// Length of the longest atom. 0 when `count` is 0.
    pub max_len: usize,
    /// Number of atoms that match the pattern exactly (no verification
    /// against the regexp VM needed).
    pub exact_count: usize,
    /// Up to [`MAX_SAMPLE_ATOMS`] sample atoms.
    pub samples: Vec<Vec<u8>>,
}

/// The heuristic that classified a pattern as slow.
///
/// The first five variants mirror the conditions checked in
/// `Compiler::c_regexp`; `CommonByteRepetition` mirrors the check for
/// repetitions of very common bytes done while processing the rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlowReason {
    /// No atoms could be extracted; the pattern must be verified at every
    /// byte of the scanned data.
    NoAtoms,
    /// A single zero-length atom was extracted. Extreme case.
    ZeroLengthAtom,
    /// The only extracted atom is shorter than 2 bytes.
    SingleShortAtom { len: usize },
    /// Multiple atoms, the shortest is below 2 bytes.
    MinAtomTooShort { min: usize, count: usize },
    /// More than 2700 atoms, all exactly 2 bytes long.
    TooManyShortAtoms { count: usize },
    /// The pattern is a repetition of a very common byte (e.g. `00`, `90`,
    /// `FF`) and is neither anchored nor modified by xor/fullword/base64.
    CommonByteRepetition,
}

impl SlowReason {
    /// Applies the slow-pattern heuristics to a sequence of atom lengths.
    /// Returns `None` if the atoms are good enough.
    pub(crate) fn from_atom_sizes<I>(sizes: I) -> Option<SlowReason>
    where
        I: IntoIterator<Item = usize>,
    {
        let mut count = 0_usize;
        let mut min = usize::MAX;
        let mut max = 0_usize;
        for len in sizes {
            count += 1;
            min = min.min(len);
            max = max.max(len);
        }
        match count {
            // No atoms, slow pattern.
            0 => Some(SlowReason::NoAtoms),
            // Only one atom of len 0. Exceptionally extreme case.
            1 if min == 0 => Some(SlowReason::ZeroLengthAtom),
            // Only one atom shorter than 2 bytes, slow pattern.
            1 if min < 2 => Some(SlowReason::SingleShortAtom { len: min }),
            // More than one atom, at least one shorter than 2 bytes.
            _ if min < 2 => Some(SlowReason::MinAtomTooShort { min, count }),
            // More than 2700 atoms, all with exactly 2 bytes. Why 2700?
            // The larger the number of atoms the higher the odds of finding
            // one of them in the data, which slows down the scan. The regex
            // [A-Za-z]{N,} (with N>=2) produces (26+26)^2 = 2704 atoms. So,
            // 2700 is large enough, but produces a warning with the
            // aforementioned regex.
            _ if min == 2 && max == 2 && count > 2700 => {
                Some(SlowReason::TooManyShortAtoms { count })
            }
            // In all other cases the pattern is not slow.
            _ => None,
        }
    }
}

/// A sub-expression identified as a likely cause of poor atom extraction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Culprit {
    /// An unbounded repetition (`.*`, `.+`, `\w*`, ...) at the start or end
    /// of the pattern.
    UnboundedRepetitionAtEdge { leading: bool, expr: String },
    /// A repetition of a large character class, e.g. `[A-Za-z]{2,}`. Forces
    /// every combination of class elements to become an atom.
    LargeClassRepetition { class_size: usize, min_rep: u32, expr: String },
    /// An alternation where the shortest branch caps the minimum atom
    /// length, e.g. `(foobar|ab)`.
    ShortAlternationBranch { min_branch_len: usize, expr: String },
    /// Nested unbounded repetitions, e.g. `(\w+)*`.
    NestedUnboundedRepetition { expr: String },
    /// A literal region shorter than the desired atom size sitting next to
    /// an arbitrary gap, typical of hex patterns like `{ 00 [1-10] 01 }`.
    ShortFixedRegion { len: usize },
}

#[cfg(test)]
mod tests {
    use super::SlowReason;

    #[test]
    fn slow_reason_from_atom_sizes() {
        assert_eq!(
            SlowReason::from_atom_sizes(std::iter::empty()),
            Some(SlowReason::NoAtoms)
        );
        assert_eq!(
            SlowReason::from_atom_sizes([0]),
            Some(SlowReason::ZeroLengthAtom)
        );
        assert_eq!(
            SlowReason::from_atom_sizes([1]),
            Some(SlowReason::SingleShortAtom { len: 1 })
        );
        // A single atom of length >= 2 is fine.
        assert_eq!(SlowReason::from_atom_sizes([2]), None);
        // Multiple atoms, one shorter than 2 bytes.
        assert_eq!(
            SlowReason::from_atom_sizes([4, 1, 4]),
            Some(SlowReason::MinAtomTooShort { min: 1, count: 3 })
        );
        // A zero-length atom among others is MinAtomTooShort, not
        // ZeroLengthAtom (which requires it to be the only atom).
        assert_eq!(
            SlowReason::from_atom_sizes([0, 4]),
            Some(SlowReason::MinAtomTooShort { min: 0, count: 2 })
        );
        // 2701 atoms of exactly 2 bytes -> too many short atoms.
        assert_eq!(
            SlowReason::from_atom_sizes(std::iter::repeat_n(2, 2701)),
            Some(SlowReason::TooManyShortAtoms { count: 2701 })
        );
        // 2700 atoms of 2 bytes is still acceptable.
        assert_eq!(
            SlowReason::from_atom_sizes(std::iter::repeat_n(2, 2700)),
            None
        );
        // Mixed lengths with min >= 2 are fine regardless of count.
        assert_eq!(
            SlowReason::from_atom_sizes(std::iter::repeat_n(3, 5000)),
            None
        );
    }
}
```

Note: if `std::iter::repeat_n` is unavailable on the toolchain, use `std::iter::repeat(2).take(2701)` instead.

- [ ] **Step 2: Declare the module**

In `lib/src/compiler/mod.rs`, add to the module declarations block (after line 81 `pub mod errors;`, keeping alphabetical order):

```rust
pub mod diagnostics;
```

- [ ] **Step 3: Run the test, verify it passes**

Run: `cargo test -p yara-x --lib diagnostics::`
Expected: `slow_reason_from_atom_sizes` PASS.

- [ ] **Step 4: Commit**

```bash
cargo fmt --all
git add lib/src/compiler/diagnostics/mod.rs lib/src/compiler/mod.rs
git commit -m "feat: add pattern diagnostics types and SlowReason heuristic"
```

---

### Task 2: Refactor `c_regexp` to use `SlowReason` (behavior-preserving)

**Files:**
- Modify: `lib/src/compiler/mod.rs:2558-2603` (inside `c_regexp`)

- [ ] **Step 1: Replace the inline minmax heuristic**

In `c_regexp` (`lib/src/compiler/mod.rs`), replace the block from `let (slow_pattern, note) =` (line 2558) through the end of the `if slow_pattern { ... }` block (line 2603) with:

```rust
        let slow_reason = diagnostics::SlowReason::from_atom_sizes(
            re_atoms.iter().map(|re_atom| re_atom.atom.len()),
        );

        if let Some(reason) = &slow_reason {
            let note = if matches!(
                reason,
                diagnostics::SlowReason::ZeroLengthAtom
            ) {
                Some(
                    "this is an exceptionally extreme case that may severely degrade scanning throughput"
                        .to_string(),
                )
            } else {
                None
            };
            if self.error_on_slow_pattern {
                return Err(errors::SlowPattern::build(
                    &self.report_builder,
                    self.report_builder.span_to_code_loc(span),
                    note,
                ));
            } else {
                self.warnings.add(|| {
                    warnings::SlowPattern::build(
                        &self.report_builder,
                        self.report_builder.span_to_code_loc(span),
                        note,
                    )
                });
            }
        }
```

Add `use crate::compiler::diagnostics;` to the import block at the top of `lib/src/compiler/mod.rs` (near line 32, `use crate::compiler::base64::base64_patterns;`) — or reference it as `diagnostics::` directly since the module is a child of `compiler` (no import needed if you use the plain `diagnostics::` path; Rust resolves sibling-module items via the implicit `self::`). Prefer the plain path, no new import.

If `MinMaxResult` (imported from itertools at line 19) is now unused, remove it from the `use itertools::{...}` list.

- [ ] **Step 2: Run the existing warning regression tests**

Run: `cargo test -p yara-x --lib warnings`
Expected: PASS — in particular the testdata cases 23, 32, 35 (slow-pattern warnings) must be unchanged.

Also run: `cargo test -p yara-x --lib errors`
Expected: PASS (covers `error_on_slow_pattern` / E018).

- [ ] **Step 3: Commit**

```bash
cargo fmt --all
git add lib/src/compiler/mod.rs
git commit -m "refactor: extract slow-pattern heuristic into SlowReason"
```

---

### Task 3: Compiler collection plumbing and public API (TDD)

**Files:**
- Modify: `lib/src/compiler/mod.rs` (struct fields ~line 256, `new()` ~line 500, public methods ~line 1015, common-byte site ~line 1610, pattern loop ~line 1821, `c_regexp` ~line 2558)
- Modify: `lib/src/lib.rs` (~line 114, public module re-export)
- Modify: `lib/src/compiler/diagnostics/mod.rs` (add integration test)

- [ ] **Step 1: Write the failing test**

Append to the `tests` module in `lib/src/compiler/diagnostics/mod.rs`:

```rust
    use super::{Culprit, PatternDiagnostics};
    use crate::Compiler;

    fn diagnostics_for(src: &str) -> Vec<PatternDiagnostics> {
        let mut compiler = Compiler::new();
        compiler.collect_pattern_diagnostics(true);
        compiler.add_source(src).unwrap();
        compiler.pattern_diagnostics().to_vec()
    }

    #[test]
    fn records_slow_regexp() {
        let diags = diagnostics_for(
            r#"rule test { strings: $a = /[A-Za-z]{2,}/ condition: $a }"#,
        );
        assert_eq!(diags.len(), 1);
        let d = &diags[0];
        assert_eq!(d.rule_name, "test");
        assert_eq!(d.pattern_ident, "$a");
        assert_eq!(
            d.slow_reason,
            Some(SlowReason::TooManyShortAtoms { count: 2704 })
        );
        let stats = d.atom_stats.as_ref().unwrap();
        assert_eq!(stats.count, 2704);
        assert_eq!(stats.min_len, 2);
        assert_eq!(stats.max_len, 2);
        assert_eq!(stats.samples.len(), super::MAX_SAMPLE_ATOMS);
    }

    #[test]
    fn records_healthy_regexp() {
        let diags = diagnostics_for(
            r#"rule test { strings: $a = /abcdefgh/ condition: $a }"#,
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].slow_reason, None);
        assert!(diags[0].atom_stats.as_ref().unwrap().min_len >= 2);
    }

    #[test]
    fn records_common_byte_repetition() {
        let diags = diagnostics_for(
            r#"rule test { strings: $a = { 00 00 00 00 } condition: $a }"#,
        );
        // One record from the common-byte-repetition check, plus one from
        // the regular compilation of the (hex) pattern.
        let cbr: Vec<_> = diags
            .iter()
            .filter(|d| {
                d.slow_reason == Some(SlowReason::CommonByteRepetition)
            })
            .collect();
        assert_eq!(cbr.len(), 1);
        assert_eq!(cbr[0].rule_name, "test");
        assert_eq!(cbr[0].pattern_ident, "$a");
        assert!(cbr[0].atom_stats.is_none());
    }

    #[test]
    fn collection_disabled_by_default() {
        let mut compiler = Compiler::new();
        compiler
            .add_source(
                r#"rule test { strings: $a = /[A-Za-z]{2,}/ condition: $a }"#,
            )
            .unwrap();
        assert!(compiler.pattern_diagnostics().is_empty());
    }
```

Note: `Culprit` is imported for Task 4's tests; if the compiler flags it unused at this point, keep the import minimal and add it in Task 4 instead.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p yara-x --lib diagnostics::`
Expected: FAIL to compile — `collect_pattern_diagnostics` and `pattern_diagnostics` don't exist yet.

- [ ] **Step 3: Add Compiler fields**

In `lib/src/compiler/mod.rs`, after the `error_on_slow_pattern: bool,` field (line 256), add:

```rust
    /// When true, the compiler records structured diagnostics about each
    /// compiled regexp/hex pattern. See
    /// [`Compiler::collect_pattern_diagnostics`].
    pattern_diagnostics_enabled: bool,

    /// Diagnostics recorded while `pattern_diagnostics_enabled` is true.
    pattern_diagnostics: Vec<diagnostics::PatternDiagnostics>,

    /// Identifier (e.g. `$a`) of the pattern currently being compiled.
    /// Tracked only while `pattern_diagnostics_enabled` is true.
    current_pattern_ident: Option<String>,
```

In `Compiler::new()` (near line 500, next to `error_on_slow_pattern: false,`), add the initializers:

```rust
            pattern_diagnostics_enabled: false,
            pattern_diagnostics: Vec::new(),
            current_pattern_ident: None,
```

- [ ] **Step 4: Add the public methods**

Next to `pub fn error_on_slow_pattern` (line 1015), add:

```rust
    /// When enabled, the compiler records structured diagnostics about every
    /// compiled regexp and hex pattern: which slow-pattern heuristic fired
    /// (if any), statistics about the extracted atoms, and the
    /// sub-expressions that hurt atom extraction. Retrieve the records with
    /// [`Compiler::pattern_diagnostics`]. Disabled by default.
    pub fn collect_pattern_diagnostics(&mut self, yes: bool) -> &mut Self {
        self.pattern_diagnostics_enabled = yes;
        self
    }

    /// Returns the diagnostics recorded so far. Empty unless
    /// [`Compiler::collect_pattern_diagnostics`] was enabled before calling
    /// [`Compiler::add_source`].
    pub fn pattern_diagnostics(&self) -> &[diagnostics::PatternDiagnostics] {
        &self.pattern_diagnostics
    }
```

- [ ] **Step 5: Capture the pattern identifier**

In the pattern-processing loop (`lib/src/compiler/mod.rs:1818-1823`), the code currently reads:

```rust
            if pending_patterns.contains(pattern_id) {
                let pattern_span = pattern.span().clone();
                match pattern.into_pattern() {
```

Change it to:

```rust
            if pending_patterns.contains(pattern_id) {
                let pattern_span = pattern.span().clone();
                if self.pattern_diagnostics_enabled {
                    self.current_pattern_ident =
                        Some(pattern.identifier().name.to_string());
                }
                match pattern.into_pattern() {
```

- [ ] **Step 6: Record diagnostics in `c_regexp`**

In `c_regexp`, right after the `let slow_reason = ...` statement added in Task 2, insert:

```rust
        if self.pattern_diagnostics_enabled {
            self.record_pattern_diagnostics(
                &re_atoms,
                slow_reason.clone(),
                span.clone(),
            );
        }
```

Then add this private method to the same `impl` block (place it right before `fn c_regexp`):

```rust
    /// Records a [`diagnostics::PatternDiagnostics`] entry for the pattern
    /// segment that is currently being compiled. Only called when
    /// `pattern_diagnostics_enabled` is true.
    fn record_pattern_diagnostics(
        &mut self,
        re_atoms: &[re::RegexpAtom],
        slow_reason: Option<diagnostics::SlowReason>,
        span: Span,
    ) {
        let rule_name = self
            .rules
            .last()
            .and_then(|rule| self.ident_pool.get(rule.ident_id))
            .unwrap_or_default()
            .to_string();

        let mut min_len = usize::MAX;
        let mut max_len = 0_usize;
        let mut exact_count = 0_usize;
        let mut samples = Vec::new();
        for re_atom in re_atoms {
            min_len = min_len.min(re_atom.atom.len());
            max_len = max_len.max(re_atom.atom.len());
            if re_atom.atom.is_exact() {
                exact_count += 1;
            }
            if samples.len() < diagnostics::MAX_SAMPLE_ATOMS {
                samples.push(re_atom.atom.as_ref().to_vec());
            }
        }

        self.pattern_diagnostics.push(diagnostics::PatternDiagnostics {
            rule_name,
            pattern_ident: self
                .current_pattern_ident
                .clone()
                .unwrap_or_default(),
            span,
            slow_reason,
            atom_stats: Some(diagnostics::AtomStats {
                count: re_atoms.len(),
                min_len: if re_atoms.is_empty() { 0 } else { min_len },
                max_len,
                exact_count,
                samples,
            }),
            culprits: Vec::new(), // populated in Task 4
        });
    }
```

- [ ] **Step 7: Record the common-byte-repetition case**

At `lib/src/compiler/mod.rs:1610-1621`, the code currently reads:

```rust
                if let Some(literal_bytes) = literal_bytes
                    && Self::common_byte_repetition(literal_bytes)
                {
                    self.warnings.add(|| {
```

Change it to:

```rust
                if let Some(literal_bytes) = literal_bytes
                    && Self::common_byte_repetition(literal_bytes)
                {
                    if self.pattern_diagnostics_enabled {
                        self.pattern_diagnostics.push(
                            diagnostics::PatternDiagnostics {
                                rule_name: rule.identifier.name.to_string(),
                                pattern_ident: pat
                                    .identifier()
                                    .name
                                    .to_string(),
                                span: pat.span().clone(),
                                slow_reason: Some(
                                    diagnostics::SlowReason::CommonByteRepetition,
                                ),
                                atom_stats: None,
                                culprits: Vec::new(),
                            },
                        );
                    }
                    self.warnings.add(|| {
```

(`rule` is the `&ast::Rule` argument of the enclosing function; `pat` is the loop variable over `rule_patterns`.)

- [ ] **Step 8: Export the public API from lib.rs**

In `lib/src/lib.rs`, after the `pub mod warnings { ... }` block (~line 114), add:

```rust
pub mod diagnostics {
    //! Structured pattern-slowness diagnostics.
    //!
    //! See [`crate::Compiler::collect_pattern_diagnostics`].
    pub use crate::compiler::diagnostics::{
        AtomStats, Culprit, MAX_SAMPLE_ATOMS, PatternDiagnostics, SlowReason,
    };
}
```

- [ ] **Step 9: Run the tests, verify they pass**

Run: `cargo test -p yara-x --lib diagnostics::`
Expected: all 5 tests PASS.

Run: `cargo test -p yara-x --lib warnings`
Expected: PASS (no behavior change for normal compiles).

- [ ] **Step 10: Commit**

```bash
cargo fmt --all
git add lib/src/compiler/mod.rs lib/src/compiler/diagnostics/mod.rs lib/src/lib.rs
git commit -m "feat: record per-pattern diagnostics in the compiler (opt-in)"
```

---

### Task 4: HIR culprit walker (TDD)

**Files:**
- Create: `lib/src/compiler/diagnostics/hir_analysis.rs`
- Modify: `lib/src/compiler/diagnostics/mod.rs` (module decl)
- Modify: `lib/src/re/hir.rs` (inner accessor)
- Modify: `lib/src/compiler/mod.rs` (`record_pattern_diagnostics` signature and call)

- [ ] **Step 1: Write the walker with table-driven tests**

Create `lib/src/compiler/diagnostics/hir_analysis.rs`:

```rust
/*! Walks a regexp HIR looking for sub-expressions that are known to hurt
atom extraction. Produces [`Culprit`] findings — facts only; the fix
suggestions live in the CLI. */

use regex_syntax::hir::{Class, Hir, HirKind};

use super::Culprit;
use crate::compiler::atoms::DESIRED_ATOM_SIZE;

/// Classes with at least this many elements are considered "large" when
/// repeated: atom extraction must enumerate every combination of class
/// elements, and the atom count grows exponentially.
const LARGE_CLASS_SIZE: usize = 16;

/// Classes that match (almost) any byte — like `.` or the implicit class of
/// a hex jump `[1-10]` — are treated as gaps rather than content.
const ANY_BYTE_CLASS_SIZE: usize = 250;

/// Returns the culprit findings for the given pattern HIR. Best-effort: an
/// empty result does not mean the pattern is fast.
pub(crate) fn find_culprits(hir: &Hir) -> Vec<Culprit> {
    let mut culprits = Vec::new();
    edge_repetitions(hir, &mut culprits);
    visit(hir, &mut culprits);
    short_fixed_regions(hir, &mut culprits);
    culprits
}

/// Number of elements the class matches.
fn class_size(class: &Class) -> usize {
    match class {
        Class::Unicode(c) => c
            .ranges()
            .iter()
            .map(|r| (r.end() as u32 - r.start() as u32) as usize + 1)
            .sum(),
        Class::Bytes(c) => c
            .ranges()
            .iter()
            .map(|r| (r.end() - r.start()) as usize + 1)
            .sum(),
    }
}

fn is_unbounded_rep(hir: &Hir) -> bool {
    matches!(hir.kind(), HirKind::Repetition(rep) if rep.max.is_none())
}

/// Flags unbounded repetitions at the very start or end of the pattern.
/// YARA patterns are unanchored, so a leading `.*` adds nothing and a
/// trailing one only extends matches; both prevent atom anchoring.
fn edge_repetitions(hir: &Hir, culprits: &mut Vec<Culprit>) {
    match hir.kind() {
        HirKind::Repetition(rep) if rep.max.is_none() => {
            culprits.push(Culprit::UnboundedRepetitionAtEdge {
                leading: true,
                expr: hir.to_string(),
            });
        }
        HirKind::Concat(subs) => {
            if let Some(first) = subs.first()
                && is_unbounded_rep(first)
            {
                culprits.push(Culprit::UnboundedRepetitionAtEdge {
                    leading: true,
                    expr: first.to_string(),
                });
            }
            if let Some(last) = subs.last()
                && is_unbounded_rep(last)
            {
                culprits.push(Culprit::UnboundedRepetitionAtEdge {
                    leading: false,
                    expr: last.to_string(),
                });
            }
        }
        _ => {}
    }
}

/// Recursive visitor for repetition and alternation culprits.
fn visit(hir: &Hir, culprits: &mut Vec<Culprit>) {
    match hir.kind() {
        HirKind::Repetition(rep) => {
            if let HirKind::Class(class) = rep.sub.kind() {
                let size = class_size(class);
                if (LARGE_CLASS_SIZE..ANY_BYTE_CLASS_SIZE).contains(&size) {
                    culprits.push(Culprit::LargeClassRepetition {
                        class_size: size,
                        min_rep: rep.min,
                        expr: hir.to_string(),
                    });
                }
            }
            if rep.max.is_none() && contains_unbounded_rep(&rep.sub) {
                culprits.push(Culprit::NestedUnboundedRepetition {
                    expr: hir.to_string(),
                });
            }
            visit(&rep.sub, culprits);
        }
        HirKind::Alternation(branches) => {
            let min_branch = branches
                .iter()
                .filter_map(|b| b.properties().minimum_len())
                .min();
            if let Some(min) = min_branch
                && min < DESIRED_ATOM_SIZE
            {
                culprits.push(Culprit::ShortAlternationBranch {
                    min_branch_len: min,
                    expr: hir.to_string(),
                });
            }
            for branch in branches {
                visit(branch, culprits);
            }
        }
        HirKind::Concat(subs) => {
            for sub in subs {
                visit(sub, culprits);
            }
        }
        HirKind::Capture(cap) => visit(&cap.sub, culprits),
        _ => {}
    }
}

fn contains_unbounded_rep(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Repetition(rep) => {
            rep.max.is_none() || contains_unbounded_rep(&rep.sub)
        }
        HirKind::Concat(subs) | HirKind::Alternation(subs) => {
            subs.iter().any(contains_unbounded_rep)
        }
        HirKind::Capture(cap) => contains_unbounded_rep(&cap.sub),
        _ => false,
    }
}

/// Flags literal regions shorter than [`DESIRED_ATOM_SIZE`] that sit right
/// next to an any-byte gap, typical of hex patterns like `{ 00 [1-10] 01 }`.
fn short_fixed_regions(hir: &Hir, culprits: &mut Vec<Culprit>) {
    let HirKind::Concat(subs) = hir.kind() else { return };
    let is_gap = |h: &Hir| {
        matches!(
            h.kind(),
            HirKind::Repetition(rep) if matches!(
                rep.sub.kind(),
                HirKind::Class(class) if class_size(class) >= ANY_BYTE_CLASS_SIZE
            )
        )
    };
    for (i, sub) in subs.iter().enumerate() {
        if let HirKind::Literal(lit) = sub.kind() {
            let len = lit.0.len();
            let prev_gap = i > 0 && is_gap(&subs[i - 1]);
            let next_gap = i + 1 < subs.len() && is_gap(&subs[i + 1]);
            if len < DESIRED_ATOM_SIZE && (prev_gap || next_gap) {
                culprits.push(Culprit::ShortFixedRegion { len });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hir(pattern: &str) -> Hir {
        regex_syntax::ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn kinds(pattern: &str) -> Vec<&'static str> {
        find_culprits(&hir(pattern))
            .iter()
            .map(|c| match c {
                Culprit::UnboundedRepetitionAtEdge { .. } => "edge_rep",
                Culprit::LargeClassRepetition { .. } => "large_class",
                Culprit::ShortAlternationBranch { .. } => "short_alt",
                Culprit::NestedUnboundedRepetition { .. } => "nested_rep",
                Culprit::ShortFixedRegion { .. } => "short_fixed",
            })
            .collect()
    }

    #[test]
    fn leading_unbounded_repetition() {
        assert!(kinds(r".*abcdef").contains(&"edge_rep"));
        assert!(kinds(r"\w+abcdef").contains(&"edge_rep"));
    }

    #[test]
    fn trailing_unbounded_repetition() {
        assert!(kinds(r"abcdef.*").contains(&"edge_rep"));
    }

    #[test]
    fn no_edge_repetition_in_middle() {
        assert!(!kinds(r"abcd.*efgh").contains(&"edge_rep"));
    }

    #[test]
    fn large_class_repetition() {
        let culprits = find_culprits(&hir(r"[A-Za-z]{2,}"));
        assert!(culprits.iter().any(|c| matches!(
            c,
            Culprit::LargeClassRepetition { class_size: 52, min_rep: 2, .. }
        )));
        // `.` is an any-byte class, not a "large class".
        assert!(!kinds(r"abcd.{2,}efgh").contains(&"large_class"));
    }

    #[test]
    fn short_alternation_branch() {
        let culprits = find_culprits(&hir(r"(?:foobar|ab)cd"));
        assert!(culprits.iter().any(|c| matches!(
            c,
            Culprit::ShortAlternationBranch { min_branch_len: 2, .. }
        )));
        assert!(!kinds(r"(?:foobar|abcd)").contains(&"short_alt"));
    }

    #[test]
    fn nested_unbounded_repetition() {
        assert!(kinds(r"(?:\w+)*").contains(&"nested_rep"));
        assert!(!kinds(r"abcd\w*").contains(&"nested_rep"));
    }

    #[test]
    fn short_fixed_region() {
        // Equivalent of the hex pattern { 00 [1-10] 01 }: a 1-byte literal
        // next to a bounded any-byte gap.
        assert!(kinds(r"\x00.{1,10}\x01").contains(&"short_fixed"));
        assert!(!kinds(r"abcdef.{1,10}ghijkl").contains(&"short_fixed"));
    }

    #[test]
    fn healthy_pattern_has_no_culprits() {
        assert!(kinds(r"abcdefgh").is_empty());
    }
}
```

Caveats for the implementer:
- `regex_syntax` may simplify HIRs during parsing (e.g. coalesce literals, rewrite repetitions). If an assertion fails, print the HIR with `dbg!(hir("..."))`, look at the actual shape, and adjust the *detector* (not the test's intent). The intent of each test is the contract.
- With `unicode(false)`, `\w` is the ASCII class (63 elements) — large but not any-byte; `.` is bytes `0x00-0xFF` minus `\n` (255 elements) — any-byte. These land on the intended sides of the thresholds.
- `rep.min` is `u32` in `regex_syntax::hir::Repetition`.

- [ ] **Step 2: Declare the submodule**

In `lib/src/compiler/diagnostics/mod.rs`, add at the top (after the module doc comment):

```rust
pub(crate) mod hir_analysis;
```

- [ ] **Step 3: Run the walker tests**

Run: `cargo test -p yara-x --lib hir_analysis`
Expected: all tests PASS (after any detector adjustments per the caveats above).

- [ ] **Step 4: Expose the inner HIR and wire the walker into recording**

In `lib/src/re/hir.rs`, inside `impl Hir` (next to `pub fn kind`, line ~226), add:

```rust
    /// Returns a reference to the underlying [`regex_syntax::hir::Hir`].
    pub(crate) fn inner(&self) -> &regex_syntax::hir::Hir {
        &self.inner
    }
```

In `lib/src/compiler/mod.rs`, change `record_pattern_diagnostics` to take the HIR and run the walker:

- Signature becomes:

```rust
    fn record_pattern_diagnostics(
        &mut self,
        hir: &re::hir::Hir,
        re_atoms: &[re::RegexpAtom],
        slow_reason: Option<diagnostics::SlowReason>,
        span: Span,
    ) {
```

- The `culprits: Vec::new(), // populated in Task 4` line becomes:

```rust
            culprits: diagnostics::hir_analysis::find_culprits(hir.inner()),
```

- The call site in `c_regexp` becomes:

```rust
        if self.pattern_diagnostics_enabled {
            self.record_pattern_diagnostics(
                hir,
                &re_atoms,
                slow_reason.clone(),
                span.clone(),
            );
        }
```

- [ ] **Step 5: Add an end-to-end culprit test**

Append to the `tests` module in `lib/src/compiler/diagnostics/mod.rs`:

```rust
    #[test]
    fn records_culprits() {
        let diags = diagnostics_for(
            r#"rule test { strings: $a = /[A-Za-z]{2,}/ condition: $a }"#,
        );
        assert!(diags[0].culprits.iter().any(|c| matches!(
            c,
            Culprit::LargeClassRepetition { class_size: 52, .. }
        )));
    }
```

- [ ] **Step 6: Run all lib tests**

Run: `cargo test -p yara-x --lib`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add lib/src/compiler/diagnostics/ lib/src/re/hir.rs lib/src/compiler/mod.rs
git commit -m "feat: detect culprit sub-expressions in slow patterns via HIR analysis"
```

---

### Task 5: CLI `yr diagnose` subcommand with text report

**Files:**
- Create: `cli/src/commands/diagnose.rs`
- Modify: `cli/src/commands/mod.rs:1-20` (mod decl + re-export), `:67-78` (subcommands vec)
- Modify: `cli/src/main.rs:85-97` (dispatch match)
- Create: `cli/src/tests/diagnose.rs`
- Modify: `cli/src/tests/mod.rs` (mod decl)

- [ ] **Step 1: Write failing integration tests**

Create `cli/src/tests/diagnose.rs`:

```rust
use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use assert_fs::prelude::*;
use predicates::prelude::*;

#[test]
fn diagnose_reports_slow_pattern() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rules.yar");
    input_file
        .write_str(
            r#"rule slow_rule { strings: $a = /[A-Za-z]{2,}/ condition: $a }"#,
        )
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("diagnose")
        .arg(input_file.path())
        .assert()
        .stdout(predicate::str::contains("slow_rule"))
        .stdout(predicate::str::contains("$a"))
        .stdout(predicate::str::contains("SLOW"))
        .stdout(predicate::str::contains("2704 atoms"))
        .stdout(predicate::str::contains("suggest"))
        .success();
}

#[test]
fn diagnose_quiet_on_healthy_rules() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rules.yar");
    input_file
        .write_str(
            r#"rule ok_rule { strings: $a = /abcdefgh/ condition: $a }"#,
        )
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("diagnose")
        .arg(input_file.path())
        .assert()
        .stdout(predicate::str::contains("SLOW").not())
        .stdout(predicate::str::contains("0 slow pattern(s)"))
        .success();
}

#[test]
fn diagnose_all_patterns_includes_healthy() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rules.yar");
    input_file
        .write_str(
            r#"rule ok_rule { strings: $a = /abcdefgh/ condition: $a }"#,
        )
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("diagnose")
        .arg("--all-patterns")
        .arg(input_file.path())
        .assert()
        .stdout(predicate::str::contains("ok_rule"))
        .stdout(predicate::str::contains("$a"))
        .success();
}

#[test]
fn diagnose_fails_on_compile_error() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rules.yar");
    input_file.write_str("rule broken {").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("diagnose")
        .arg(input_file.path())
        .assert()
        .failure();
}
```

Register it in `cli/src/tests/mod.rs` (alphabetical order with the other `mod` lines):

```rust
mod diagnose;
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p yara-x-cli diagnose`
Expected: FAIL — the subcommand doesn't exist (`error: unrecognized subcommand`).

- [ ] **Step 3: Implement the subcommand**

Create `cli/src/commands/diagnose.rs`:

```rust
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{Arg, ArgAction, ArgMatches, Command, arg};
use yansi::Color::{Cyan, Red};
use yansi::Paint;

use yara_x::SourceCode;
use yara_x::diagnostics::{
    AtomStats, Culprit, PatternDiagnostics, SlowReason,
};

use crate::commands::{
    compilation_args, create_compiler, get_external_vars,
    path_with_namespace_parser,
};
use crate::config::Config;
use crate::walk::Walker;

pub fn diagnose() -> Command {
    super::command("diagnose")
        .about("Explain why patterns are slow")
        .long_about(
            "Compiles the rules with diagnostics collection enabled and \
             reports, for each slow pattern, which heuristic flagged it, \
             the atoms extracted from it, the sub-expression that hurts \
             atom extraction, and a fix suggestion.",
        )
        .arg(
            Arg::new("[NAMESPACE:]RULES_PATH")
                .required(true)
                .help("Path to a YARA source file or directory (optionally prefixed with a namespace)")
                .value_parser(path_with_namespace_parser)
                .action(ArgAction::Append),
        )
        .args(itertools::merge(
            compilation_args(),
            [
                arg!(--"all-patterns")
                    .help("Report every analyzed pattern, not only slow ones"),
                arg!(--"output-format" <FORMAT>)
                    .help("Output format")
                    .value_parser(["text", "json"])
                    .default_value("text"),
            ],
        ))
}

/// A source file that was fed to the compiler, paired with the cumulative
/// number of diagnostics records that existed right after compiling it.
/// Used to map a record index back to the file it came from.
struct CompiledSource {
    path: PathBuf,
    content: String,
    diags_so_far: usize,
}

pub fn exec_diagnose(
    args: &ArgMatches,
    config: &Config,
) -> anyhow::Result<()> {
    let rules_path = args
        .get_many::<(Option<String>, PathBuf)>("[NAMESPACE:]RULES_PATH")
        .unwrap();
    let all_patterns = args.get_flag("all-patterns");
    let json_output =
        args.get_one::<String>("output-format").unwrap() == "json";

    let external_vars = get_external_vars(args);
    let mut compiler = create_compiler(external_vars, args, config)?;
    compiler.collect_pattern_diagnostics(true);

    let mut sources: Vec<CompiledSource> = Vec::new();

    for (namespace, path) in rules_path {
        let mut w = Walker::path(path);
        w.filter("**/*.yar");
        w.filter("**/*.yara");

        compiler.new_namespace(namespace.as_deref().unwrap_or("default"));

        w.walk(
            |file_path| {
                let content =
                    fs::read_to_string(file_path).with_context(|| {
                        format!("can not read `{}`", file_path.display())
                    })?;

                let src = SourceCode::from(content.as_bytes()).with_origin(
                    file_path.as_os_str().to_str().unwrap(),
                );

                if args.get_flag("path-as-namespace") {
                    compiler
                        .new_namespace(file_path.to_string_lossy().as_ref());
                }

                let _ = compiler.add_source(src);

                sources.push(CompiledSource {
                    path: file_path.into(),
                    content,
                    diags_so_far: compiler.pattern_diagnostics().len(),
                });

                Ok(())
            },
            Err,
        )?;
    }

    for error in compiler.errors() {
        eprintln!("{error}");
    }

    if !compiler.errors().is_empty() {
        bail!("{} error(s) found", compiler.errors().len());
    }

    let diags = compiler.pattern_diagnostics();

    let selected: Vec<(usize, &PatternDiagnostics)> = diags
        .iter()
        .enumerate()
        .filter(|(_, d)| all_patterns || d.slow_reason.is_some())
        .collect();

    let file_for = |idx: usize| -> &CompiledSource {
        sources.iter().find(|s| idx < s.diags_so_far).unwrap()
    };

    if json_output {
        print_json(&selected, file_for);
    } else {
        print_text(&selected, file_for);
        let num_slow =
            diags.iter().filter(|d| d.slow_reason.is_some()).count();
        println!(
            "{} slow pattern(s) found, {} pattern(s) analyzed",
            num_slow,
            diags.len()
        );
    }

    Ok(())
}

/// Returns the 1-based (line, column) of a byte offset within `content`.
fn line_col(content: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(content.len());
    let before = &content[..offset];
    let line = before.matches('\n').count() + 1;
    let line_start = before.rfind('\n').map(|p| p + 1).unwrap_or(0);
    (line, offset - line_start + 1)
}

fn verdict(d: &PatternDiagnostics) -> String {
    match &d.slow_reason {
        Some(SlowReason::NoAtoms) => {
            "no atoms could be extracted; the pattern must be verified at \
             every byte of the scanned data"
                .to_string()
        }
        Some(SlowReason::ZeroLengthAtom) => {
            "a zero-length atom was extracted; this is an exceptionally \
             extreme case that may severely degrade scanning throughput"
                .to_string()
        }
        Some(SlowReason::SingleShortAtom { len }) => {
            format!("the only extracted atom is just {len} byte(s) long")
        }
        Some(SlowReason::MinAtomTooShort { min, count }) => format!(
            "{count} atoms extracted, the shortest is only {min} byte(s) long"
        ),
        Some(SlowReason::TooManyShortAtoms { count }) => {
            format!("{count} atoms extracted, all only 2 bytes long")
        }
        Some(SlowReason::CommonByteRepetition) => {
            "the pattern is a repetition of a very common byte, which \
             appears in huge runs in many files"
                .to_string()
        }
        None => "no slowness detected".to_string(),
    }
}

fn culprit_text(c: &Culprit) -> String {
    match c {
        Culprit::UnboundedRepetitionAtEdge { leading, expr } => format!(
            "`{}` — unbounded repetition at the {} of the pattern prevents \
             atom anchoring",
            expr,
            if *leading { "start" } else { "end" }
        ),
        Culprit::LargeClassRepetition { class_size, min_rep, expr } => {
            format!(
                "`{expr}` — repetition (min {min_rep}) of a \
                 {class_size}-element class forces every combination to \
                 become an atom"
            )
        }
        Culprit::ShortAlternationBranch { min_branch_len, expr } => format!(
            "`{expr}` — the shortest alternation branch is only \
             {min_branch_len} byte(s), capping the atom length"
        ),
        Culprit::NestedUnboundedRepetition { expr } => format!(
            "`{expr}` — nested unbounded repetitions produce no usable atoms"
        ),
        Culprit::ShortFixedRegion { len } => format!(
            "a fixed region of only {len} byte(s) sits next to an \
             arbitrary gap"
        ),
    }
}

fn culprit_suggestion(c: &Culprit) -> &'static str {
    match c {
        Culprit::UnboundedRepetitionAtEdge { leading: true, .. } => {
            "remove the leading repetition; YARA patterns are unanchored, \
             so a leading `.*` adds nothing and hurts atom extraction"
        }
        Culprit::UnboundedRepetitionAtEdge { leading: false, .. } => {
            "remove the trailing repetition or bound it (e.g. `{0,N}`)"
        }
        Culprit::LargeClassRepetition { .. } => {
            "add at least 4 fixed bytes next to the class repetition, or \
             narrow the character class"
        }
        Culprit::ShortAlternationBranch { .. } => {
            "make every alternation branch at least 4 bytes long, or move \
             the alternation away from the only fixed part of the pattern"
        }
        Culprit::NestedUnboundedRepetition { .. } => {
            "flatten nested repetitions (e.g. replace `(\\w+)*` with `\\w*`)"
        }
        Culprit::ShortFixedRegion { .. } => {
            "extend the fixed bytes around the gap to at least 4 bytes, or \
             split the pattern in two and combine them in the condition"
        }
    }
}

fn reason_suggestion(r: &SlowReason) -> &'static str {
    match r {
        SlowReason::CommonByteRepetition => {
            "anchor the pattern to nearby distinctive bytes, use a fixed \
             offset (e.g. `$a at 0`), or add xor/fullword/base64 modifiers \
             if applicable"
        }
        SlowReason::TooManyShortAtoms { .. } => {
            "raise the minimum repetition count or add a fixed \
             prefix/suffix so longer atoms can be extracted"
        }
        _ => {
            "add at least 4 consecutive fixed bytes (outside any class, \
             alternation or repetition) anywhere in the pattern"
        }
    }
}

fn atoms_line(stats: &AtomStats) -> String {
    let samples = stats
        .samples
        .iter()
        .map(|s| format!("\"{}\"", s.escape_ascii()))
        .collect::<Vec<_>>()
        .join(" ");
    let ellipsis = if stats.count > stats.samples.len() { " …" } else { "" };
    format!(
        "count={}, len min={} max={}, exact={}   sample: {}{}",
        stats.count,
        stats.min_len,
        stats.max_len,
        stats.exact_count,
        samples,
        ellipsis
    )
}

fn print_text<'a>(
    selected: &[(usize, &PatternDiagnostics)],
    file_for: impl Fn(usize) -> &'a CompiledSource,
) {
    for (idx, d) in selected {
        let src = file_for(*idx);
        let start = d.span.0.start as usize;
        let end = (d.span.0.end as usize).min(src.content.len());
        let (line, col) = line_col(&src.content, start);
        let status = if d.slow_reason.is_some() {
            "SLOW".paint(Red).bold().to_string()
        } else {
            "OK".paint(Cyan).to_string()
        };
        println!(
            "rule {} — {} is {}    {}:{}:{}",
            d.rule_name.bold(),
            d.pattern_ident.bold(),
            status,
            src.path.display(),
            line,
            col
        );
        println!("  pattern : {}", &src.content[start..end]);
        println!("  verdict : {}", verdict(d));
        if let Some(stats) = &d.atom_stats {
            println!("  atoms   : {}", atoms_line(stats));
        }
        for culprit in &d.culprits {
            println!("  culprit : {}", culprit_text(culprit));
            println!("  suggest : {}", culprit_suggestion(culprit));
        }
        if d.culprits.is_empty()
            && let Some(reason) = &d.slow_reason
        {
            println!("  suggest : {}", reason_suggestion(reason));
        }
        println!();
    }
}

fn print_json<'a>(
    selected: &[(usize, &PatternDiagnostics)],
    file_for: impl Fn(usize) -> &'a CompiledSource,
) {
    let entries: Vec<serde_json::Value> = selected
        .iter()
        .map(|(idx, d)| {
            let src = file_for(*idx);
            let start = d.span.0.start as usize;
            let end = (d.span.0.end as usize).min(src.content.len());
            let (line, col) = line_col(&src.content, start);
            serde_json::json!({
                "rule": d.rule_name,
                "pattern": d.pattern_ident,
                "file": src.path.display().to_string(),
                "line": line,
                "column": col,
                "source": &src.content[start..end],
                "slow": d.slow_reason.is_some(),
                "verdict": verdict(d),
                "atoms": d.atom_stats.as_ref().map(|s| serde_json::json!({
                    "count": s.count,
                    "min_len": s.min_len,
                    "max_len": s.max_len,
                    "exact": s.exact_count,
                    "samples": s.samples
                        .iter()
                        .map(|b| b.escape_ascii().to_string())
                        .collect::<Vec<_>>(),
                })),
                "culprits": d.culprits.iter().map(|c| serde_json::json!({
                    "detail": culprit_text(c),
                    "suggestion": culprit_suggestion(c),
                })).collect::<Vec<_>>(),
                "suggestion": d.slow_reason.as_ref()
                    .map(|r| reason_suggestion(r)),
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::Value::Array(entries))
            .unwrap()
    );
}
```

- [ ] **Step 4: Wire the command into the CLI**

In `cli/src/commands/mod.rs`:
- Add `mod diagnose;` to the module list (line 1-9, alphabetical: after `mod deps;`).
- Add `pub use diagnose::*;` to the re-exports (after `pub use deps::*;`).
- Add `commands::diagnose(),` to the `subcommands(vec![...])` list (line 67-78, after `commands::deps(),`).

In `cli/src/main.rs`, add to the dispatch match (line 85-97, next to the other arms):

```rust
        Some(("diagnose", args)) => commands::exec_diagnose(args, &config),
```

- [ ] **Step 5: Run the integration tests**

Run: `cargo test -p yara-x-cli diagnose`
Expected: all 4 tests PASS. (Note: assert_cmd output is uncolored because stdout is not a tty, so `contains("SLOW")` matches the unpainted text.)

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add cli/src/commands/diagnose.rs cli/src/commands/mod.rs cli/src/main.rs cli/src/tests/diagnose.rs cli/src/tests/mod.rs
git commit -m "feat: add yr diagnose subcommand with verbose slow-pattern report"
```

---

### Task 6: JSON output test

**Files:**
- Modify: `cli/src/tests/diagnose.rs`

(The JSON renderer was implemented in Task 5; this task locks it in with a test.)

- [ ] **Step 1: Write the test**

Append to `cli/src/tests/diagnose.rs`:

```rust
#[test]
fn diagnose_json_output() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rules.yar");
    input_file
        .write_str(
            r#"rule slow_rule { strings: $a = /[A-Za-z]{2,}/ condition: $a }"#,
        )
        .unwrap();

    let output = Command::new(cargo_bin!("yr"))
        .arg("diagnose")
        .arg("--output-format=json")
        .arg(input_file.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value =
        serde_json::from_slice(&output).expect("output is valid JSON");
    let entries = parsed.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["rule"], "slow_rule");
    assert_eq!(entries[0]["pattern"], "$a");
    assert_eq!(entries[0]["slow"], true);
    assert_eq!(entries[0]["atoms"]["count"], 2704);
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p yara-x-cli diagnose_json`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
cargo fmt --all
git add cli/src/tests/diagnose.rs
git commit -m "test: cover yr diagnose JSON output"
```

---

### Task 7: `--scan` runtime mode (feature-gated, phase 2)

**Files:**
- Modify: `cli/src/commands/diagnose.rs`
- Modify: `cli/src/tests/diagnose.rs`

The CLI crate already defines the feature: `cli/Cargo.toml:45` has `rules-profiling = ["yara-x/rules-profiling"]`. The scanner API is `Scanner::slowest_rules(n) -> Vec<ProfilingData>` with fields `namespace`, `rule`, `condition_exec_time`, `pattern_matching_time` (`lib/src/scanner/mod.rs:153-165`, gated by `#[cfg(feature = "rules-profiling")]`).

- [ ] **Step 1: Add the cfg-gated `--scan` argument**

In `cli/src/commands/diagnose.rs`, restructure `diagnose()` so the command is built into a `let mut cmd = ...` binding and the final expression returns it, then add before the return:

```rust
    #[cfg(feature = "rules-profiling")]
    {
        cmd = cmd.arg(
            clap::arg!(--"scan" <SAMPLE_PATH>)
                .help(
                    "Scan a sample file or directory and report per-rule \
                     timing alongside the static findings",
                )
                .value_parser(clap::value_parser!(PathBuf)),
        );
    }
    cmd
```

- [ ] **Step 2: Implement the runtime mode in `exec_diagnose`**

In `exec_diagnose`, the static report borrows `compiler` immutably while `Compiler::build()` consumes it, so clone the diagnostics first. Change the post-error-check section to:

```rust
    let diags: Vec<PatternDiagnostics> =
        compiler.pattern_diagnostics().to_vec();
```

(and adjust `selected` to borrow from `diags` — the rest of the rendering code is unchanged since it already works on references).

Then, at the end of `exec_diagnose`, before `Ok(())`:

```rust
    #[cfg(feature = "rules-profiling")]
    if let Some(sample_path) = args.get_one::<PathBuf>("scan") {
        scan_and_report(compiler, sample_path, &diags)?;
    }
```

And add the function (cfg-gated, at the bottom of the file):

```rust
#[cfg(feature = "rules-profiling")]
fn scan_and_report(
    compiler: yara_x::Compiler,
    sample_path: &PathBuf,
    diags: &[PatternDiagnostics],
) -> anyhow::Result<()> {
    use std::time::Duration;

    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);

    let mut w = Walker::path(sample_path);
    w.walk(
        |file_path| {
            let data = fs::read(file_path).with_context(|| {
                format!("can not read `{}`", file_path.display())
            })?;
            let _ = scanner.scan(&data);
            Ok(())
        },
        Err,
    )?;

    let slowest = scanner.slowest_rules(20);

    if slowest.is_empty() {
        println!("no profiling data collected");
        return Ok(());
    }

    let total: Duration = slowest
        .iter()
        .map(|p| p.condition_exec_time + p.pattern_matching_time)
        .sum();

    println!("slowest rules while scanning `{}`:", sample_path.display());
    for p in &slowest {
        let rule_time = p.condition_exec_time + p.pattern_matching_time;
        let pct = if total.as_nanos() > 0 {
            rule_time.as_nanos() as f64 / total.as_nanos() as f64 * 100.0
        } else {
            0.0
        };
        println!(
            "rule {}:{} — {:.2?} ({:.0}% of profiled time; condition \
             {:.2?}, patterns {:.2?})",
            p.namespace,
            p.rule,
            rule_time,
            pct,
            p.condition_exec_time,
            p.pattern_matching_time,
        );
        let slow_idents: Vec<&str> = diags
            .iter()
            .filter(|d| d.rule_name == p.rule && d.slow_reason.is_some())
            .map(|d| d.pattern_ident.as_str())
            .collect();
        if !slow_idents.is_empty() {
            println!(
                "  statically-flagged slow patterns in this rule: {} \
                 (details above)",
                slow_idents.join(", ")
            );
        }
    }

    Ok(())
}
```

Note: `ProfilingData` borrows from the scanner; keep `slowest` usage within the scanner's lifetime as shown. If the borrow checker complains about `scanner` vs `rules` lifetimes, extract the printable data into owned tuples first.

- [ ] **Step 3: Add the feature-gated test**

Append to `cli/src/tests/diagnose.rs`:

```rust
#[cfg(feature = "rules-profiling")]
#[test]
fn diagnose_scan_reports_rule_timing() {
    let temp_dir = TempDir::new().unwrap();
    let rules_file = temp_dir.child("rules.yar");
    rules_file
        .write_str(
            r#"rule slow_rule { strings: $a = /[A-Za-z]{2,}/ condition: $a }"#,
        )
        .unwrap();
    let sample_file = temp_dir.child("sample.bin");
    sample_file
        .write_str(&"The quick brown fox jumps over the lazy dog. ".repeat(2000))
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("diagnose")
        .arg("--scan")
        .arg(sample_file.path())
        .arg(rules_file.path())
        .assert()
        .stdout(predicate::str::contains("slowest rules"))
        .stdout(predicate::str::contains("slow_rule"))
        .success();
}
```

- [ ] **Step 4: Build and test both with and without the feature**

Run: `cargo test -p yara-x-cli diagnose`
Expected: PASS (scan test skipped — not compiled without the feature).

Run: `cargo test -p yara-x-cli --features rules-profiling diagnose`
Expected: PASS including `diagnose_scan_reports_rule_timing`.

(Note: `cargo_bin!` integration tests build the `yr` binary with the same feature set as the test crate, so the feature flag flows through.)

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add cli/src/commands/diagnose.rs cli/src/tests/diagnose.rs
git commit -m "feat: add --scan runtime profiling mode to yr diagnose"
```

---

### Task 8: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Full workspace test run**

Run: `cargo test --workspace`
Expected: PASS. Pay attention to lib warning/error snapshot tests — the Task 2 refactor must not have changed any warning text.

- [ ] **Step 2: Lints and formatting**

Run: `cargo clippy --workspace --all-targets` and `cargo fmt --all -- --check`
Expected: no new warnings, no formatting diffs. Fix anything that appears and amend.

- [ ] **Step 3: Manual smoke test**

```bash
cargo run -p yara-x-cli -- diagnose lib/src/compiler/tests/testdata/warnings/35.in
```

Expected output (shape, not byte-exact): a `rule test — $a is SLOW` block with pattern `/[A-Za-z]{2,}/`, verdict `2704 atoms extracted, all only 2 bytes long`, a `LargeClassRepetition` culprit line, a suggestion, and the `1 slow pattern(s) found` summary. Note: testdata files have a `.in` extension, so if the walker filter skips them, copy the content to a `/tmp/slow.yar` file for the smoke test.

- [ ] **Step 4: Commit any remaining fixes**

```bash
git status   # should be clean; commit stragglers if any
```

---

## Out of scope (per spec)

- Per-pattern (vs per-rule) runtime timing — would require VM instrumentation.
- Automatic pattern rewriting ("full advisor").
- Recording diagnostics for plain text literal patterns (they don't go through `c_regexp`; the common-byte-repetition check still covers their worst case).
- Upstream-quality API stability; this is fork-internal.
