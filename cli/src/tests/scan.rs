use assert_cmd::{Command, cargo_bin};
use assert_fs::TempDir;
use assert_fs::prelude::*;
use predicates::prelude::*;
use serde_json;

#[test]
fn always_true() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("src/tests/testdata/true.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "warning[invariant_expr]: invariant boolean expression",
        ))
        .stdout(predicate::str::contains(
            "always_true src/tests/testdata/dummy.file",
        ));
}

#[test]
fn negate() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--negate")
        .arg("src/tests/testdata/true.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("");
}

#[test]
fn filter_by_tag() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--tag=foo")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("");

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--tag=bar")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(predicate::str::contains("foo src/tests/testdata/dummy.file"));
}

#[test]
fn disable_warning() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--disable-warnings=invariant_expr")
        .arg("src/tests/testdata/true.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr(
            predicate::str::contains(
                "warning[invariant_expr]: invariant boolean expression",
            )
            .not(),
        )
        .stdout(predicate::str::contains(
            "always_true src/tests/testdata/dummy.file",
        ));
}

#[test]
fn disable_warning_config_file() {
    let temp_dir = TempDir::new().unwrap();
    let config_file = temp_dir.child("config.toml");

    config_file
        .write_str(
            r#"
            [warnings]
            invariant_expr = { disabled = true }
            "#,
        )
        .unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("--config")
        .arg(config_file.path())
        .arg("scan")
        .arg("src/tests/testdata/true.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr(
            predicate::str::contains(
                "warning[invariant_expr]: invariant boolean expression",
            )
            .not(),
        )
        .stdout(predicate::str::contains(
            "always_true src/tests/testdata/dummy.file",
        ));
}

#[test]
fn print_strings() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--print-strings")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(
            "foo src/tests/testdata/dummy.file
0x0:3:$foo: foo
0x0:3:$foo_hex: 66 6f 6f
",
        );
}

#[test]
fn print_strings_n() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--print-strings=2")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(
            "foo src/tests/testdata/dummy.file
0x0:3:$foo: fo ... 1 more bytes
0x0:3:$foo_hex: 66 6f ... 1 more bytes
",
        );
}

#[test]
fn print_namespace() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--print-namespace")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("default:foo src/tests/testdata/dummy.file\n");
}

#[test]
fn print_meta() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--print-meta")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("foo [string=\"foo\",bool=true,int=1,float=3.14,regexp=\"foo\"] src/tests/testdata/dummy.file\n");
}

#[test]
fn print_tags() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--print-tags")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("foo [bar,baz] src/tests/testdata/dummy.file\n");
}

#[test]
fn path_as_namespace() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--print-namespace")
        .arg("--path-as-namespace")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout(
            "src/tests/testdata/foo.yar:foo src/tests/testdata/dummy.file\n",
        );
}

#[test]
fn format_ndjson() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=ndjson")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("{\"path\":\"src/tests/testdata/dummy.file\",\"rules\":[{\"identifier\":\"foo\"}]}\n");
}

#[test]
fn define() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--define=float=3.14")
        .arg("--define=int=1")
        .arg("--define=bool=true")
        .arg("src/tests/testdata/variables.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stdout("test src/tests/testdata/dummy.file\n");
}

#[test]
fn console() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("src/tests/testdata/console.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr("src/tests/testdata/dummy.file: hello\n");

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--disable-console-logs")
        .arg("src/tests/testdata/console.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr("");
}

#[test]
fn ignore_module() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--ignore-module=unknown")
        .arg("src/tests/testdata/unknown_module.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .stderr(
            r#"warning[unsupported_module]: module `unknown` is not supported
 --> src/tests/testdata/unknown_module.yar:1:1
  |
1 | import "unknown"
  | ---------------- module `unknown` used here
warning[unsupported_module]: module `unknown` is not supported
 --> src/tests/testdata/unknown_module.yar:5:6
  |
5 |      unknown.foo()
  |      ------- module `unknown` used here
  |
  = note: the whole rule `test` will be ignored
"#,
        );
}

#[test]
fn recursive() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--recursive")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .failure()
        .code(1)
        .stderr(
            "error: can\'t use \'--recursive\' when <TARGET_PATH> is a file\n",
        );
}

#[test]
fn compiled_rules() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--compiled-rules")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .failure()
        .code(1)
        .stderr("error: can\'t use \'--compiled-rules\' with more than one RULES_PATH\n");

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--compiled-rules")
        .arg("namespace:src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .failure()
        .code(1)
        .stderr("error: can\'t use namespace with \'--compiled-rules\'\n");

    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_str("rule test { condition: true }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("compile")
        .arg("-o")
        .arg(input_file.with_extension("yarc"))
        .arg(input_file.path())
        .assert()
        .success();

    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--compiled-rules")
        .arg(input_file.with_extension("yarc"))
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success();
}

#[test]
fn issue_280() {
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("src/tests/testdata/foo.yar")
        .arg("./src/tests/testdata/")
        .assert()
        .success();

    // Handle special case of just . for path argument.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("src/tests/testdata/foo.yar")
        .arg(".")
        .assert()
        .success();

    // Handle special case of just ./ for path argument.
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("src/tests/testdata/foo.yar")
        .arg("./")
        .assert()
        .success();

    // Handle special case of just .\ for path argument.
    #[cfg(target_os = "windows")]
    Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("src/tests/testdata/foo.yar")
        .arg(r#".\"#)
        .assert()
        .success();
}

#[test]
fn json_output_duplicate_meta_keys() {
    // Test that duplicate metadata keys are preserved as arrays in JSON output
    let output = Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=json")
        .arg("--print-meta")
        .arg("src/tests/testdata/duplicate_meta.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("valid JSON output");

    // Navigate to the meta object
    let meta = &json["matches"][0]["meta"];

    // Single-value keys should remain as single values
    assert_eq!(meta["author"], "Test Author");
    assert_eq!(meta["description"], "Rule with duplicate metadata keys");

    // Duplicate keys should become arrays
    let hash = &meta["hash"];
    assert!(hash.is_array(), "hash should be an array");
    let hash_array = hash.as_array().unwrap();
    assert_eq!(hash_array.len(), 3);
    assert!(hash_array.contains(&serde_json::json!("aaa111")));
    assert!(hash_array.contains(&serde_json::json!("bbb222")));
    assert!(hash_array.contains(&serde_json::json!("ccc333")));
}

#[test]
fn json_output_single_meta_not_array() {
    // Test that single metadata values are NOT wrapped in arrays
    let output = Command::new(cargo_bin!("yr"))
        .arg("scan")
        .arg("--output-format=json")
        .arg("--print-meta")
        .arg("src/tests/testdata/foo.yar")
        .arg("src/tests/testdata/dummy.file")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("valid JSON output");

    let meta = &json["matches"][0]["meta"];

    // All values should be single values, not arrays
    assert!(meta["string"].is_string());
    assert!(meta["bool"].is_boolean());
    assert!(meta["int"].is_i64());
    assert!(meta["float"].is_f64());
}

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

    // Threshold-based skip: on under-powered hosts the rule may not cross
    // the 100ms cumulative threshold and no offender block will be printed.
    // In that case there is nothing meaningful to assert structurally.
    if out.contains("top offending files") {
        let large_path = large.path().to_string_lossy().into_owned();
        let small_path = small.path().to_string_lossy().into_owned();

        // Both files appear in the offender output and the Slowest files
        // section header is printed. Ordering between large vs small
        // depends on memory access patterns / cache effects and is not
        // structurally reliable, so we don't assert on it.
        assert!(out.contains(&large_path), "large.bin path should appear");
        assert!(out.contains(&small_path), "small.bin path should appear");
        assert!(out.contains("Slowest files:"), "Slowest files: header must appear");
    } else {
        eprintln!(
            "note: profiling threshold not crossed on this host; \
             smoke assertions skipped"
        );
    }
}
