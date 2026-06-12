use std::fs;
#[cfg(feature = "rules-profiling")]
use std::path::Path;
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
    #[allow(unused_mut)]
    let mut cmd = super::command("diagnose")
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
        ));

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

                let src = SourceCode::from(content.as_bytes())
                    .with_origin(file_path.as_os_str().to_str().unwrap());

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

    // Cloned because `--scan` consumes the compiler via `build()`.
    let diags: Vec<PatternDiagnostics> =
        compiler.pattern_diagnostics().to_vec();

    let selected: Vec<(usize, &PatternDiagnostics)> = diags
        .iter()
        .enumerate()
        .filter(|(_, d)| all_patterns || d.slow_reason.is_some())
        .collect();

    if json_output {
        print_json(&selected, &sources);
    } else {
        print_text(&selected, &sources);
        let num_slow =
            diags.iter().filter(|d| d.slow_reason.is_some()).count();
        println!(
            "{} slow pattern(s) found, {} pattern(s) analyzed",
            num_slow,
            diags.len()
        );
    }

    #[cfg(feature = "rules-profiling")]
    if let Some(sample_path) = args.get_one::<PathBuf>("scan") {
        scan_and_report(compiler, sample_path, &diags)?;
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

/// Removes regex-engine flag-group wrappers like `(?-u:...)`, `(?u:...)`,
/// `(?s:...)` or `(?i:...)` that `regex_syntax`'s HIR printer inserts but a
/// YARA author never wrote, e.g. `(?-u:[A-Za-z]){2,}` -> `[A-Za-z]{2,}`.
fn strip_flag_groups(expr: &str) -> String {
    let bytes = expr.as_bytes();
    let mut out = String::with_capacity(expr.len());
    // Stack entry: true = this open paren belongs to a dropped flag group.
    let mut stack: Vec<bool> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // Track whether the current byte is preceded by an unescaped backslash.
        let escaped = i > 0 && bytes[i - 1] == b'\\' && {
            // Count consecutive preceding backslashes; odd count → escaped.
            let n =
                bytes[..i].iter().rev().take_while(|&&b| b == b'\\').count();
            n % 2 == 1
        };

        if !escaped && bytes[i] == b'(' {
            // Detect `(?<flags>:` where <flags> is a non-empty run of [iusmx-].
            let rest = &expr[i..];
            let flag_len = rest
                .strip_prefix("(?")
                .and_then(|r| {
                    r.find(':').filter(|&n| {
                        n > 0 && r[..n].chars().all(|c| "iusmx-".contains(c))
                    })
                })
                .map(|n| 2 + n + 1); // "(?".len() + flags.len() + ":".len()

            if let Some(skip) = flag_len {
                stack.push(true);
                i += skip;
                continue;
            }
            stack.push(false);
            out.push('(');
        } else if !escaped && bytes[i] == b')' {
            if stack.pop() != Some(true) {
                out.push(')');
            }
            // else: closing paren of a dropped flag group — skip it
        } else {
            // Push the next full Unicode scalar (handles multibyte chars).
            let ch = expr[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        i += 1;
    }
    out
}

fn culprit_text(c: &Culprit) -> String {
    match c {
        Culprit::UnboundedRepetitionAtEdge { leading, expr } => format!(
            "`{}` — unbounded repetition at the {} of the pattern prevents \
             atom anchoring",
            strip_flag_groups(expr),
            if *leading { "start" } else { "end" }
        ),
        Culprit::LargeClassRepetition { class_size, min_rep, expr } => {
            format!(
                "`{}` — repetition (min {min_rep}) of a \
                 {class_size}-element class forces every combination to \
                 become an atom",
                strip_flag_groups(expr)
            )
        }
        Culprit::ShortAlternationBranch { min_branch_len, expr } => format!(
            "`{}` — the shortest alternation branch is only \
             {min_branch_len} byte(s), capping the atom length",
            strip_flag_groups(expr)
        ),
        Culprit::NestedUnboundedRepetition { expr } => format!(
            "`{}` — nested unbounded repetitions produce no usable atoms",
            strip_flag_groups(expr)
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
            "a repetition at the start of the pattern cannot be anchored; \
             add fixed bytes before it, or if the whole pattern is one \
             repetition, narrow the repeated class or raise its minimum count"
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
        .map(|s| format!("\"{}\"", s.as_slice().escape_ascii()))
        .collect::<Vec<_>>()
        .join(" ");
    let ellipsis = if stats.count > stats.samples.len() { " …" } else { "" };
    format!(
        "{} atoms, len min={} max={}, exact={}   sample: {}{}",
        stats.count,
        stats.min_len,
        stats.max_len,
        stats.exact_count,
        samples,
        ellipsis
    )
}

fn print_text(
    selected: &[(usize, &PatternDiagnostics)],
    sources: &[CompiledSource],
) {
    let file_for = |idx: usize| -> &CompiledSource {
        sources
            .iter()
            .find(|s| idx < s.diags_so_far)
            .expect("diagnostic index has no source file")
    };

    for (idx, d) in selected {
        let src = file_for(*idx);
        let start = d.span.start();
        let end = d.span.end().min(src.content.len());
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
        if d.culprits.is_empty() {
            if let Some(reason) = &d.slow_reason {
                println!("  suggest : {}", reason_suggestion(reason));
            }
        }
        println!();
    }
}

fn print_json(
    selected: &[(usize, &PatternDiagnostics)],
    sources: &[CompiledSource],
) {
    let file_for = |idx: usize| -> &CompiledSource {
        sources
            .iter()
            .find(|s| idx < s.diags_so_far)
            .expect("diagnostic index has no source file")
    };
    let entries: Vec<serde_json::Value> = selected
        .iter()
        .map(|(idx, d)| {
            let src = file_for(*idx);
            let start = d.span.start();
            let end = d.span.end().min(src.content.len());
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
                        .map(|b| b.as_slice().escape_ascii().to_string())
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

#[cfg(feature = "rules-profiling")]
fn scan_and_report(
    compiler: yara_x::Compiler,
    sample_path: &Path,
    diags: &[PatternDiagnostics],
) -> anyhow::Result<()> {
    use std::time::Duration;

    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);

    let w = Walker::path(sample_path);
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
            "rule {}:{} — {:.2?} ({:.0}% of top-20 time; condition \
             {:.2?}, patterns {:.2?})",
            p.namespace,
            p.rule,
            rule_time,
            pct,
            p.condition_exec_time,
            p.pattern_matching_time,
        );
        let mut slow_idents: Vec<&str> = diags
            .iter()
            // TODO(namespace-join): PatternDiagnostics lacks a namespace
            // field; same-named rules in different namespaces may
            // cross-attribute findings here.
            .filter(|d| d.rule_name == p.rule && d.slow_reason.is_some())
            .map(|d| d.pattern_ident.as_str())
            .collect();
        slow_idents.sort_unstable();
        slow_idents.dedup();
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

#[cfg(test)]
mod tests {
    use super::strip_flag_groups;

    #[test]
    fn strips_flag_groups() {
        assert_eq!(strip_flag_groups("(?-u:[A-Za-z]){2,}"), "[A-Za-z]{2,}");
        assert_eq!(strip_flag_groups("(?s:.)*abc"), ".*abc");
        assert_eq!(strip_flag_groups("(?i:(?-u:ab)|cd)"), "ab|cd");
        // Non-flag groups are preserved.
        assert_eq!(strip_flag_groups("(abc)+"), "(abc)+");
        assert_eq!(strip_flag_groups("(?:abc)+"), "(?:abc)+");
        // Escaped parens are literal.
        assert_eq!(strip_flag_groups(r"\(?-u:x\)"), r"\(?-u:x\)");
        // Plain text untouched.
        assert_eq!(strip_flag_groups("abcd"), "abcd");
    }
}
