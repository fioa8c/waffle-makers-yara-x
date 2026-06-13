# `yr diagnose` — Verbose Slow-Pattern Diagnostics

**Date:** 2026-06-12
**Status:** Approved
**Scope:** Fork-internal tool (not targeted at upstream contribution)

## Problem

When the yara-x compiler decides a pattern is slow, it emits a single generic
`slow_pattern` warning. The user's only options are to ignore it or suppress it
with `-w`/`--disable-warnings=slow_pattern`. The warning does not explain
*which* part of the regex causes the slowness, what atoms were extracted, or
how to fix the pattern.

The slow-pattern verdict is produced in `Compiler::c_regexp()`
(`lib/src/compiler/mod.rs:2558-2585`) from heuristics over the atoms extracted
for the Aho-Corasick pre-filter: no atoms, atoms shorter than 2 bytes, or more
than ~2700 two-byte atoms.

## Goal

An auxiliary CLI tool that explains, per slow pattern: which heuristic fired,
what atoms were extracted, which sub-expression of the regex is the culprit,
and a fix suggestion. Optionally, it also measures real per-rule scan time
against a user-provided sample.

## Design

### 1. CLI UX

New subcommand in `cli/src/commands/diagnose.rs`:

```
yr diagnose [OPTIONS] <RULES_PATH>...
```

- **Default:** compile the rules with diagnostics collection enabled and print
  a report only for patterns flagged as slow (the same set that triggers
  today's `slow_pattern` warning).
- `--all-patterns`: report atom statistics for every pattern that goes through
  atom extraction, not just slow ones.
- `--output-format=json`: structured output for tooling; default is
  human-readable text.
- `--scan <SAMPLE_PATH>`: runtime mode (see section 4).
- Reuses the same rule-loading options as `yr compile` where sensible
  (`--define`, `--relaxed-re-syntax`, …) so diagnosis runs on the same
  compilation the user actually performs.

Example text output per finding:

```
rule my_rule — $re1 is SLOW                          src/rules/foo.yar:12:5
  pattern : /[A-Za-z]{2,}={0,2}/
  verdict : 2704 atoms extracted, all only 2 bytes long
  atoms   : count=2704, len min=2 max=2, exact=0   sample: "AA" "AB" "AC" …
  culprit : `[A-Za-z]{2,}` — repetition of a 52-character class at the
            pattern start forces every 2-byte combination to become an atom
  suggest : anchor the pattern with a longer fixed substring, or raise the
            minimum repetition so longer atoms can be extracted
```

### 2. Lib-side: diagnostics collection in the Compiler

New module `lib/src/compiler/diagnostics.rs` holding presentation-free,
structured data:

```rust
pub struct PatternDiagnostics {
    pub rule_name: String,
    pub pattern_ident: String,           // "$re1"
    pub pattern_source: CodeLoc,         // for file:line reporting
    pub slow_reason: Option<SlowReason>, // None = not slow
    pub atom_stats: AtomStats,           // count, min/max len, exact count,
                                         // up to 8 sample atoms
    pub culprits: Vec<Culprit>,          // see section 3
}

pub enum SlowReason {                    // mirrors the c_regexp heuristics
    NoAtoms,
    ZeroLengthAtom,
    SingleShortAtom { len: usize },
    MinAtomTooShort { min: usize, count: usize },
    TooManyShortAtoms { count: usize },
}
```

Compiler changes (`lib/src/compiler/mod.rs`):

- `Compiler::collect_pattern_diagnostics(bool)` builder method. Off by
  default — zero cost for normal compiles.
- In `c_regexp()`, where the `minmax()` heuristics already run, push a
  `PatternDiagnostics` record when collection is on. This covers regexp and
  hex patterns — exactly the set the slow-pattern warning covers today.
- Getter: `Compiler::pattern_diagnostics() -> &[PatternDiagnostics]`.

Key property: records are built from the same `re_atoms` vector the scanner
will use, so the report can never disagree with the actual compiler verdict.

### 3. Culprit analysis (HIR walker)

Submodule `lib/src/compiler/diagnostics/hir_analysis.rs` walks the pattern's
HIR (already in hand inside `c_regexp`) and emits structured `Culprit`
findings — each a kind plus parameters. Initial culprit catalog:

| Kind | Example | Why it hurts |
|------|---------|--------------|
| Leading/trailing unbounded repetition | `.*`, `.+`, `[^x]*` at pattern edges | kills atom anchoring |
| Large class under repetition | `[A-Za-z]{2,}` | class size × repetition explodes atom count (~2704) |
| Short alternation branch | `(foobar\|ab)` | one branch caps minimum atom length |
| Hex jump near short anchor | `{ 00 [1-10] 01 }` | gaps leave only 1–2 fixed bytes per region |
| Nested unbounded repetition | `(\w+)*` | compounding blow-up, no usable atoms |

The lib records facts (kind + spans/params + a short description); the CLI
owns the suggestion strings, mapping each culprit kind to a fix
recommendation. This keeps presentation out of the compiler. Culprit detection
is best-effort: if no specific culprit matches, the report still shows the
verdict and atom statistics.

### 4. Runtime mode (`--scan`) — phase 2

Built on the existing `rules-profiling` feature:

- The fork's CLI build enables `yara-x/rules-profiling`.
- `yr diagnose --scan <sample>` scans the sample(s) and joins `ProfilingData`
  (per-**rule** clock time — the granularity that feature offers) with the
  static findings:

```
rule my_rule — 312.4ms scan time (87% of total)
  slow patterns in this rule: $re1, $re3   (static details above)
```

Per-pattern timing would require deeper VM instrumentation and is out of
scope. Per-rule timing plus static per-pattern culprits is sufficient to act
on.

### 5. Error handling

- Rules that fail to compile: report the compile error and exit non-zero,
  same as `yr compile`. No diagnosis of uncompilable rules.
- Diagnostics are collected regardless of `-w`/warning switches — disabling
  the warning does not hide the tool's output.
- `--scan` with an unreadable sample follows the normal scan error path.

### 6. Testing

- **Lib unit tests:** assert `PatternDiagnostics` contents (reason, atom
  stats, culprit kinds) for the known slow patterns already used in warning
  testdata (`lib/src/compiler/tests/testdata/warnings/23.in`, `32.in`,
  `35.in`) plus targeted cases per culprit kind.
- **HIR walker tests:** table-driven — pattern string → expected culprit
  kinds.
- **CLI integration test:** run `diagnose` on a fixture rules file and assert
  on text and JSON output, following the existing CLI test patterns.

## Phasing

1. **Phase 1 (core):** lib diagnostics collection + culprit walker +
   `yr diagnose` static report (text + JSON).
2. **Phase 2:** `--scan` runtime mode joining `rules-profiling` data.

## Rejected alternatives

- **Standalone analyzer in the CLI crate** re-running atom extraction via
  exposed internals: duplicates the compile pipeline and will diverge from
  the real compiler over time.
- **Enriching the `SlowPattern` warning struct:** warnings are
  macro-generated, serializable, user-facing structures — a poor vehicle for
  rich diagnostic payloads, and detail would be capped by what fits in a
  warning.
