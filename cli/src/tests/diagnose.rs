use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use assert_fs::prelude::*;
use predicates::prelude::*;
use serde_json;

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
            r#"rule ok_rule { strings: $a = /abcd[0-9]efgh/ condition: $a }"#,
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
            r#"rule ok_rule { strings: $a = /abcd[0-9]efgh/ condition: $a }"#,
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
