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

    let diags = compiler.pattern_diagnostics();

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
        sources.iter().find(|s| idx < s.diags_so_far).unwrap()
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
        sources.iter().find(|s| idx < s.diags_so_far).unwrap()
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
