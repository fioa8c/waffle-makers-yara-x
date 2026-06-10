# PHP Detection Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new YARA-X module `php` exposing a single boolean field `php.is_php`, true when PHP code appears anywhere in the scanned buffer (webshell/polyglot detection).

**Architecture:** Pure-Rust, dependency-free heuristic. A `detect_php(&[u8]) -> bool` function scans the whole buffer for PHP open tags: `<?php`/`<?=` are strong signals; a bare `<?` counts only when not `<?xml` and a PHP token appears within a 256-byte window. The result is computed eagerly in the module's `main()` and stored in the proto. No external parser, no data transformation.

**Tech Stack:** Rust, protobuf module definition, YARA-X module system (`register_module!`, `build.rs` auto-discovery), `bstr`/`memchr` (already workspace deps), existing `rule_true!`/`rule_false!` test macros.

---

## Reference: spec

Design spec: `docs/superpowers/specs/2026-06-10-php-module-design.md`. Read it for rationale, false-positive posture, and rejected alternatives.

## File Structure

- **Create** `lib/src/modules/protos/php.proto` — proto defining `php.Php { bool is_php }` and `yara.module_options` (module name, root message, cargo feature). `build.rs` auto-discovers it and emits `mod php;` into the generated `lib/src/modules/modules.rs` (do not edit that generated file).
- **Create** `lib/src/modules/php.rs` — the module: `main()`, the pure `detect_php` helper and its small sub-helpers, `register_module!`, and an inline `#[cfg(test)] mod tests`.
- **Modify** `lib/Cargo.toml` — add the `php-module = []` feature and add `"php-module"` to the `default-modules` array.

`build.rs` regenerates `modules.rs` on every build because the `generate-proto-code` feature is on by default, so no manual registry edits are needed.

---

## Task 1: Scaffold the `php` module (proto + feature + stub) so `import "php"` works

**Files:**
- Create: `lib/src/modules/protos/php.proto`
- Create: `lib/src/modules/php.rs`
- Modify: `lib/Cargo.toml` (add `php-module` feature)
- Test: inline in `lib/src/modules/php.rs`

- [ ] **Step 1: Create the proto definition**

Create `lib/src/modules/protos/php.proto`:

```protobuf
syntax = "proto2";

import "yara.proto";

package php;

option (yara.module_options) = {
  name : "php"
  root_message: "php.Php"
  cargo_feature: "php-module"
};

message Php {
  // True when PHP code is detected anywhere in the scanned data.
  optional bool is_php = 1;
}
```

- [ ] **Step 2: Add the Cargo feature**

In `lib/Cargo.toml`, in the `[features]` section near the other `*-module` features (around the `magic-module` / `math-module` lines), add:

```toml
# The `php` module detects PHP code anywhere in the scanned data.
php-module = []
```

Do NOT add it to `default-modules` yet — that happens in Task 5 after it is proven to work.

- [ ] **Step 3: Create the module file with a stub `detect_php`**

Create `lib/src/modules/php.rs`:

```rust
/*! YARA module that detects the presence of PHP code.

This module exposes a single field, `php.is_php`, which is true when PHP
code is found anywhere in the scanned data. It is designed for webshell and
polyglot detection, where PHP may be appended to or embedded inside files
that other tools classify as images, HTML, or generic data.
*/
use crate::mods::prelude::*;
use crate::modules::protos::php::*;

#[cfg(test)]
mod tests;

fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Php, ModuleError> {
    let mut php = Php::new();
    php.is_php = Some(detect_php(data));
    Ok(php)
}

/// Returns true if PHP code appears anywhere in `data`.
fn detect_php(_data: &[u8]) -> bool {
    // Implemented incrementally in later tasks.
    false
}

register_module!("php", Php, main);
```

Note: the inline `mod tests;` refers to a sibling file `lib/src/modules/php/tests.rs`. To keep this module single-file like `string.rs`, instead change `mod tests;` to an inline module. Use this inline form in the file above — replace the `#[cfg(test)] mod tests;` line with the inline block created in Step 4.

- [ ] **Step 4: Add the first integration test (inline)**

In `lib/src/modules/php.rs`, replace the `#[cfg(test)]\nmod tests;` line with this inline test module (place it just above the `register_module!` line):

```rust
#[cfg(test)]
mod tests {
    use crate::tests::rule_false;
    use crate::tests::rule_true;

    #[test]
    fn module_is_importable() {
        // Empty data is never PHP; this also proves `import "php"` compiles
        // and `php.is_php` is a valid boolean field.
        rule_false!(
            r#"
            import "php"
            rule test { condition: php.is_php }"#,
            b""
        );
    }
}
```

- [ ] **Step 5: Run the test to verify it passes (wiring works)**

Run: `cargo test -p yara-x --lib --features php-module modules::php`
Expected: PASS. `module_is_importable` passes (empty data ⇒ `is_php = false` ⇒ rule does not match). This proves the proto, feature, `build.rs` regeneration, and `register_module!` are all wired correctly.

- [ ] **Step 6: Commit**

```bash
git add lib/src/modules/protos/php.proto lib/src/modules/php.rs lib/Cargo.toml lib/src/modules/modules.rs
git commit -m "feat(php): scaffold php detection module"
```

(The regenerated `lib/src/modules/modules.rs` is committed because it is a tracked, checked-in generated file.)

---

## Task 2: Detect strong signals — `<?php` (case-insensitive) and `<?=`

**Files:**
- Modify: `lib/src/modules/php.rs`
- Test: inline `mod tests` in `lib/src/modules/php.rs`

- [ ] **Step 1: Write failing unit tests for strong signals**

In the inline `mod tests` in `lib/src/modules/php.rs`, add (also add `use super::detect_php;` at the top of the test module):

```rust
#[test]
fn strong_signals() {
    assert!(detect_php(b"<?php echo 1;"));
    assert!(detect_php(b"<?PHP echo 1;"));          // case-insensitive keyword
    assert!(detect_php(b"<?= $x ?>"));               // short echo tag
    assert!(detect_php(b"GIF89a....\x00<?php system($_GET['c']);")); // polyglot
    assert!(detect_php(b"<html><body><?php phpinfo(); ?></body></html>")); // embedded
    assert!(!detect_php(b""));                        // empty
    assert!(!detect_php(b"plain text, no markers"));  // no tag
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yara-x --lib --features php-module modules::php::tests::strong_signals`
Expected: FAIL — the polyglot/`<?php` assertions fail because `detect_php` still returns `false`.

- [ ] **Step 3: Implement strong-signal detection**

In `lib/src/modules/php.rs`, replace the stub `detect_php` and add a `classify_open_tag` helper:

```rust
/// Maximum number of bytes searched after a bare `<?` for a PHP token.
const WEAK_WINDOW: usize = 256;

/// Returns true if PHP code appears anywhere in `data`.
fn detect_php(data: &[u8]) -> bool {
    // Examine every `<?` occurrence; classify what follows it.
    data.find_iter("<?").any(|pos| classify_open_tag(&data[pos + 2..]))
}

/// Classifies the bytes that follow a `<?` marker. `after` is the slice
/// starting immediately after the `<?`.
fn classify_open_tag(after: &[u8]) -> bool {
    // Strong: `<?=` short-echo tag is always PHP.
    if after.first() == Some(&b'=') {
        return true;
    }
    // Strong: `<?php` (keyword is case-insensitive).
    if after.len() >= 3 && after[..3].eq_ignore_ascii_case(b"php") {
        return true;
    }
    // Weak-signal handling is added in Task 3.
    false
}
```

`find_iter` and `find` come from `bstr::ByteSlice`, which is in scope via `use crate::mods::prelude::*;`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p yara-x --lib --features php-module modules::php::tests::strong_signals`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/src/modules/php.rs
git commit -m "feat(php): detect <?php and <?= open tags anywhere in buffer"
```

---

## Task 3: Detect the weak signal — bare `<?` with a nearby PHP token, excluding `<?xml`

**Files:**
- Modify: `lib/src/modules/php.rs`
- Test: inline `mod tests` in `lib/src/modules/php.rs`

- [ ] **Step 1: Write failing unit tests for the weak signal**

In the inline `mod tests`, add:

```rust
#[test]
fn weak_signal_short_tag() {
    // Short-tag webshell: bare `<?` + PHP token within the window.
    assert!(detect_php(b"<? eval($_POST['x']); ?>"));
    assert!(detect_php(b"<? system($_GET['c']); ?>"));
}

#[test]
fn weak_signal_rejects_non_php() {
    // XML declaration is not PHP.
    assert!(!detect_php(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(!detect_php(b"<?XML version=\"1.0\"?>")); // case-insensitive xml
    // Bare `<?` with no PHP token nearby.
    assert!(!detect_php(b"<? just some text with no php tokens at all >"));
    // A file that has both an XML declaration AND real PHP must still match.
    assert!(detect_php(b"<?xml version=\"1.0\"?>\n<root><?php echo 1;?></root>"));
}

#[test]
fn weak_signal_window_boundary() {
    // `<?` at the very end with no following bytes is not PHP.
    assert!(!detect_php(b"<?"));
    // A PHP token just beyond the 256-byte window is not detected.
    let mut buf = b"<? ".to_vec();
    buf.extend(std::iter::repeat(b'x').take(300));
    buf.extend_from_slice(b"$_GET");
    assert!(!detect_php(&buf));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yara-x --lib --features php-module modules::php::tests::weak_signal`
Expected: FAIL — `weak_signal_short_tag` fails (bare `<?` currently returns false).

- [ ] **Step 3: Implement the weak signal**

In `lib/src/modules/php.rs`, add the token tables and a window helper, and extend `classify_open_tag`:

```rust
/// PHP superglobals (case-sensitive: PHP requires the exact casing).
const PHP_SUPERGLOBALS: &[&[u8]] = &[
    b"$_GET", b"$_POST", b"$_REQUEST", b"$_SERVER", b"$_COOKIE",
    b"$_FILES", b"$_SESSION", b"$_ENV", b"$GLOBALS",
];

/// PHP functions/keywords commonly seen in webshells. PHP function and
/// keyword names are case-insensitive, so the window is lowercased before
/// matching and every entry here MUST be lowercase.
const PHP_TOKENS_CI: &[&[u8]] = &[
    b"eval", b"assert", b"system", b"exec", b"shell_exec", b"passthru",
    b"base64_decode", b"gzinflate", b"str_rot13", b"preg_replace",
    b"create_function", b"call_user_func", b"echo", b"function",
    b"print", b"require", b"include",
];

/// Returns true if `window` contains any PHP superglobal or token.
fn window_has_php_token(window: &[u8]) -> bool {
    if PHP_SUPERGLOBALS.iter().any(|sg| window.find(sg).is_some()) {
        return true;
    }
    let lower = window.to_ascii_lowercase();
    PHP_TOKENS_CI.iter().any(|tok| lower.find(tok).is_some())
}
```

Then replace the `// Weak-signal handling is added in Task 3.` comment and the `false` below it in `classify_open_tag` with:

```rust
    // `<?xml` is an XML declaration / processing instruction, not PHP.
    if after.len() >= 3 && after[..3].eq_ignore_ascii_case(b"xml") {
        return false;
    }
    // Weak: a bare `<?` counts only if a PHP token appears within the window.
    let end = after.len().min(WEAK_WINDOW);
    window_has_php_token(&after[..end])
```

The final `classify_open_tag` reads: strong `<?=` → true; strong `<?php` → true; `<?xml` → false; otherwise weak-window token probe.

- [ ] **Step 4: Run to verify all unit tests pass**

Run: `cargo test -p yara-x --lib --features php-module modules::php`
Expected: PASS — `strong_signals`, `weak_signal_short_tag`, `weak_signal_rejects_non_php`, `weak_signal_window_boundary`, and `module_is_importable` all pass.

- [ ] **Step 5: Commit**

```bash
git add lib/src/modules/php.rs
git commit -m "feat(php): detect short-tag PHP via token window, exclude <?xml"
```

---

## Task 4: Rule-level integration tests and short-circuit usage example

**Files:**
- Modify: `lib/src/modules/php.rs` (inline `mod tests`)

- [ ] **Step 1: Write rule-level integration tests**

In the inline `mod tests`, add tests that exercise the module through compiled rules (not just the helper):

```rust
#[test]
fn rule_detects_php() {
    rule_true!(
        r#"
        import "php"
        rule test { condition: php.is_php }"#,
        b"<?php echo 1;"
    );

    // Polyglot: PHP appended after an image header.
    rule_true!(
        r#"
        import "php"
        rule test { condition: php.is_php }"#,
        b"GIF89a\x01\x00\x01\x00<?php system($_GET['c']); ?>"
    );
}

#[test]
fn rule_rejects_non_php() {
    rule_false!(
        r#"
        import "php"
        rule test { condition: php.is_php }"#,
        b"<?xml version=\"1.0\"?><note><to>x</to></note>"
    );

    rule_false!(
        r#"
        import "php"
        rule test { condition: php.is_php }"#,
        b"just plain text"
    );
}

#[test]
fn rule_short_circuit_gate() {
    // Documents the intended usage: `php.is_php` first gates the patterns.
    // On non-PHP data the pattern is never searched and the rule is false.
    rule_false!(
        r#"
        import "php"
        rule php_webshell {
            strings: $a = "eval($_POST"
            condition: php.is_php and $a
        }"#,
        b"this file is not php and contains eval($_POST as plain text"
    );

    // On PHP data with the pattern present, the rule matches.
    rule_true!(
        r#"
        import "php"
        rule php_webshell {
            strings: $a = "eval($_POST"
            condition: php.is_php and $a
        }"#,
        b"<?php eval($_POST['x']); ?>"
    );
}
```

Note on `rule_short_circuit_gate`: the first case is `rule_false` because the data is not PHP, so `php.is_php` is false and the `and` short-circuits before `$a` is searched — exactly the behavior the gate relies on. The test asserts the observable result (no match); it does not (and cannot easily) assert that the search was skipped, but the spec documents that mechanism.

- [ ] **Step 2: Run to verify the new tests pass**

Run: `cargo test -p yara-x --lib --features php-module modules::php`
Expected: PASS for all tests including `rule_detects_php`, `rule_rejects_non_php`, `rule_short_circuit_gate`.

- [ ] **Step 3: Commit**

```bash
git add lib/src/modules/php.rs
git commit -m "test(php): rule-level integration tests and short-circuit gate example"
```

---

## Task 5: Enable by default, verify full build, fmt/clippy, final commit

**Files:**
- Modify: `lib/Cargo.toml` (add `"php-module"` to `default-modules`)
- Modify: `lib/src/modules/php.rs` (only if fmt/clippy require)

- [ ] **Step 1: Add the module to `default-modules`**

In `lib/Cargo.toml`, in the `default-modules` array, add `"php-module"` (keep the list readable; placement need not be alphabetical but near the other modules):

```toml
default-modules = [
    "console-module",
    ...
    "vt-module",
    "php-module",
]
```

- [ ] **Step 2: Run the full module test suite with default features**

Run: `cargo test -p yara-x --lib modules::php`
Expected: PASS (now without needing `--features php-module`, since it is a default module).

- [ ] **Step 3: Run formatter and clippy**

Run: `cargo fmt -p yara-x` then `cargo clippy -p yara-x --lib --features php-module -- -D warnings`
Expected: no formatting diff left unstaged after re-adding, and clippy passes with no warnings. Fix any clippy findings in `lib/src/modules/php.rs` and re-run.

- [ ] **Step 4: Build the whole crate to confirm nothing else broke**

Run: `cargo build -p yara-x`
Expected: builds successfully. (Confirms `build.rs` regenerated `modules.rs` with `php` enabled by default and the crate compiles.)

- [ ] **Step 5: Commit**

```bash
git add lib/Cargo.toml lib/src/modules/php.rs lib/src/modules/modules.rs
git commit -m "feat(php): enable php module by default"
```

---

## Self-Review (completed during planning)

- **Spec coverage:**
  - `php.is_php` boolean output — Task 1 (proto) + Task 1 `main()`. ✓
  - Detect anywhere in buffer / strong signals `<?php`,`<?=` — Task 2. ✓
  - Weak `<?` + token window, `<?xml` exclusion, recall focus — Task 3. ✓
  - Short-circuit usage guidance — Task 4 `rule_short_circuit_gate` test + spec doc. ✓
  - Pure Rust, no native dep, ship in `default-modules` — Task 5. ✓
  - Tunables (token list, 256-byte window) — encoded as `PHP_SUPERGLOBALS`/`PHP_TOKENS_CI`/`WEAK_WINDOW` constants in Task 3. ✓
  - Non-goals (no AST, no transform, no validity proof) — respected; nothing in the plan adds them. ✓
- **Placeholder scan:** No TBD/TODO in delivered code. Task 1's `detect_php` returns `false` as an explicit, tested intermediate state (replaced in Task 2), not a placeholder left at the end.
- **Type consistency:** `detect_php(&[u8]) -> bool`, `classify_open_tag(&[u8]) -> bool`, `window_has_php_token(&[u8]) -> bool`, constants `WEAK_WINDOW`/`PHP_SUPERGLOBALS`/`PHP_TOKENS_CI` — names used consistently across Tasks 2–4. Proto message `Php` with field `is_php` matches `php.proto` and `main()`.

## Notes for the implementer

- The generated file `lib/src/modules/modules.rs` is checked into the repo and rewritten by `build.rs` on build. Stage it whenever it changes (Tasks 1 and 5).
- All test commands run from the repository root.
- If `cargo test` reports the `php` module is not found, ensure a build ran first so `build.rs` regenerated `modules.rs`; `cargo test` does this automatically but a stale editor state can hide it.
