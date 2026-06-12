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
        Class::Bytes(c) => {
            c.ranges().iter().map(|r| (r.end() - r.start()) as usize + 1).sum()
        }
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
