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
    /// Total number of atoms extracted from the pattern.
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
/// All variants except `CommonByteRepetition` mirror the conditions checked in
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
    SingleShortAtom {
        /// Length of the sole extracted atom.
        len: usize,
    },
    /// Multiple atoms, the shortest is below 2 bytes.
    MinAtomTooShort {
        /// Length of the shortest atom.
        min: usize,
        /// Total number of atoms extracted.
        count: usize,
    },
    /// More than 2700 atoms, all exactly 2 bytes long.
    TooManyShortAtoms {
        /// Total number of atoms extracted.
        count: usize,
    },
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
    UnboundedRepetitionAtEdge {
        /// `true` if the repetition is at the leading edge; `false` if trailing.
        leading: bool,
        /// Source text of the repetition sub-expression.
        expr: String,
    },
    /// A repetition of a large character class, e.g. `[A-Za-z]{2,}`. Forces
    /// every combination of class elements to become an atom.
    LargeClassRepetition {
        /// Number of elements in the character class.
        class_size: usize,
        /// Minimum repetition count.
        min_rep: u32,
        /// Source text of the repetition sub-expression.
        expr: String,
    },
    /// An alternation where the shortest branch caps the minimum atom
    /// length, e.g. `(foobar|ab)`.
    ShortAlternationBranch {
        /// Length (in bytes) of the shortest branch in the alternation.
        min_branch_len: usize,
        /// Source text of the alternation sub-expression.
        expr: String,
    },
    /// Nested unbounded repetitions, e.g. `(\w+)*`.
    NestedUnboundedRepetition {
        /// Source text of the outer repetition sub-expression.
        expr: String,
    },
    /// A literal region shorter than the desired atom size sitting next to
    /// an arbitrary gap, typical of hex patterns like `{ 00 [1-10] 01 }`.
    ShortFixedRegion {
        /// Length of the fixed literal region in bytes.
        len: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::PatternDiagnostics;
    use super::SlowReason;
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
            SlowReason::from_atom_sizes(std::iter::repeat(2).take(2701)),
            Some(SlowReason::TooManyShortAtoms { count: 2701 })
        );
        // 2700 atoms of 2 bytes is still acceptable.
        assert_eq!(
            SlowReason::from_atom_sizes(std::iter::repeat(2).take(2700)),
            None
        );
        // Mixed lengths with min >= 2 are fine regardless of count.
        assert_eq!(
            SlowReason::from_atom_sizes(std::iter::repeat(3).take(5000)),
            None
        );
    }
}
