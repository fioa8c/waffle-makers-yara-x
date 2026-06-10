# PHP Detection Module — Design

**Date:** 2026-06-10
**Status:** Approved design, ready for implementation planning
**Component:** `lib/src/modules/` (new `php` module)

## Summary

Add a new YARA-X module named `php` that exposes a single boolean field,
`php.is_php`, which is `true` when PHP code is present **anywhere** in the
scanned buffer. The module targets webshell and polyglot detection: PHP that is
appended to or embedded inside files that another tool (e.g. libmagic) would
classify as an image, HTML, or generic `data`.

Detection is a pure-Rust, dependency-free heuristic scan over the whole buffer.
There is no parsing, no file transformation, and no external parser
(mago/php-parser were considered and rejected — see Rejected Alternatives).

## Goals

- Expose `php.is_php : bool` to rule conditions.
- Detect PHP open tags located **anywhere** in the buffer, not just near the
  start (this is the gap over libmagic's `magic.type()` / `magic.mime_type()`).
- Optimize for **recall** on evasive/obfuscated PHP while keeping false
  positives on XML and binary data acceptably low.
- Be lightweight enough to ship in `default-modules` (pure Rust, no native deps,
  unlike the `magic` module which depends on libmagic and is *not* a default
  module).

## Non-Goals

- No AST / structural fields (no `php.uses_eval`, `php.includes`, etc.). Output
  is exactly one boolean. (Explicitly de-scoped during brainstorming.)
- No transformation of the scanned bytes and no influence over *which* bytes the
  pattern engine matches. The YARA-X module API receives `&[u8]` immutably and
  cannot rewrite the data stream. "Prepare the file before scanning" is achieved
  only as a condition-level gate (see Short-Circuit Behavior), not as a data
  transform.
- No PHP version/variant identification.
- No proof of syntactic validity (we deliberately do not require the candidate
  to parse as valid PHP — webshells are frequently malformed/obfuscated).

## Detection Algorithm

The module's `main()` receives the full buffer and returns a `Php` protobuf with
`is_php` set. The decision is made by a single scan for PHP open-tag markers,
classified by strength:

### Strong signals (any one ⇒ `is_php = true`)

- `<?php` — case-insensitive on the `php` keyword, i.e. matches `<?PHP`,
  `<?Php`, etc. May be preceded by any bytes (handles `GIF89a...<?php`,
  HTML-then-PHP, leading BOM/whitespace).
- `<?=` — the short-echo tag, which is always PHP regardless of
  `short_open_tag` configuration.

### Weak signal (bare `<?`)

A bare `<?` that is **not** one of the strong forms is ambiguous: it is also how
XML declarations (`<?xml`), XML processing instructions, and incidental binary
bytes appear. A bare `<?` counts toward `is_php` only when **both** hold:

1. It is **not** `<?xml` (case-insensitive), and not immediately followed by a
   character that makes it a recognized non-PHP processing instruction. (We
   special-case `xml`; other PIs are rare enough to treat the bare `<?`
   normally.)
2. Within a bounded window after the `<?` (proposed: **256 bytes**, capped at
   end of buffer) at least one **PHP token indicator** appears. Proposed token
   set (literal, case-insensitive where noted):
   - Superglobals: `$_GET`, `$_POST`, `$_REQUEST`, `$_SERVER`, `$_COOKIE`,
     `$_FILES`, `$_SESSION`, `$_ENV`, `$GLOBALS`
   - Common shell/eval primitives: `eval`, `assert`, `system`, `exec`,
     `shell_exec`, `passthru`, `base64_decode`, `gzinflate`, `str_rot13`,
     `preg_replace`, `create_function`, `call_user_func`
   - Language keywords/sigils: `<?php` is already strong; for weak we look for
     `echo`, `function`, `print`, `require`, `include`, and the PHP statement
     terminator pattern `;` preceded by a `$variable`.

   The token set is a tunable constant. The intent is "a bare `<?` plus evidence
   of PHP semantics nearby," which catches `short_open_tag` webshells while
   rejecting plain XML and random binary.

### Result

`is_php` is `true` if any strong signal is found, or any qualifying weak signal
is found. Otherwise `false`. The field is always set (never left undefined) so
that `not php.is_php` behaves predictably.

### Performance

- Single pass; the search for `<?` candidates should use a fast substring search
  (e.g. `memchr`-based, already a dependency in the workspace) rather than a
  regex. For each `<?` candidate we do an O(1)-bounded classification and, for
  weak candidates, a bounded 256-byte token probe.
- Result is computed once in `main()` and stored in the returned proto; rules
  reading `php.is_php` incur no rescans. (No thread-local cache needed because,
  unlike the `magic` module's lazy exported functions, this is computed eagerly
  in `main()`.)

### False-positive / false-negative posture

- Known acceptable false positives: a non-PHP file that literally contains
  `<?php` as a string (e.g. documentation about PHP, a tutorial, this very spec).
  This is inherent to signature-style detection and acceptable for the
  webshell-hunting use case.
- Known limits: PHP that contains *no* open tag at all (rare; pure included
  fragments) will not be detected — by design, since open tags are the defining
  marker. Heavily split/obfuscated tags (e.g. `'<?'.'php'` constructed at
  runtime) are out of scope for v1.

## Module Interface

### Proto definition — `lib/src/modules/protos/php.proto`

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
  optional bool is_php = 1;
}
```

### Rust implementation — `lib/src/modules/php.rs` (single-file module)

```rust
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
fn detect_php(data: &[u8]) -> bool {
    // strong-signal scan + bounded weak-signal classification (see algorithm)
}

register_module!("php", Php, main);
```

The detection helper(s) live in the same file (the algorithm is small). No
`#[module_export]` functions are needed — there are no callable functions, only
the `is_php` field populated by `main()`.

## Build / Registration Integration

1. **`lib/src/modules/protos/php.proto`** — created as above. `build.rs`
   auto-discovers any `.proto` with `yara.module_options` and wires up generated
   code and field docs; no manual edit to a registry is required.
2. **`lib/src/modules/php.rs`** — created; `register_module!("php", Php, main)`
   registers it at link time via `inventory`.
3. **`lib/Cargo.toml`** —
   - Add feature: `php-module = []` (no extra deps; `memchr` is already
     available in the workspace).
   - Add `"php-module"` to the `default-modules` array so it ships by default.
   (Pure Rust + no native dependency means, unlike `magic`, it is safe to enable
   by default.)

No changes to `scanner` or `compiler` are needed — module dispatch is generic.

## Usage & Short-Circuit Behavior (for rule authors / docs)

YARA-X searches patterns **lazily**: the Aho-Corasick pattern pass runs only the
first time a condition references a `$pattern`, and module `main()` runs before
conditions. Therefore `php.is_php` can act as a gate that avoids the pattern
search entirely on non-PHP buffers:

```yara
import "php"

rule php_webshell {
    strings:
        $a = "eval($_POST"
        $b = "assert($_REQUEST"
    condition:
        php.is_php and ($a or $b)   // is_php FIRST
}
```

Guidance to document:

- **Order matters.** `php.is_php` must be the **first** operand of the `and`.
  `($a or $b) and php.is_php` triggers the search before the gate and saves
  nothing.
- **The search is shared.** Once *any* active rule references a pattern, the
  single shared pass searches *all* patterns for *all* rules. The savings
  materialize only when **every** pattern-bearing rule in the scan is gated
  (e.g. a dedicated PHP-webshell ruleset).
- **Namespace gate.** A `global rule must_be_php { condition: php.is_php }`
  suppresses all rules in its namespace when `is_php` is false. Treat the
  explicit `php.is_php and ...` form as the guaranteed-fast pattern; whether the
  global rule also skips the search depends on evaluation order and is a
  secondary optimization.
- **True pre-filtering** (never scanning non-PHP files at all) still requires the
  embedding application to check before calling `Scanner::scan()`. The module
  cannot transform or skip data on its own.

## Testing

Follow the existing module test convention (per-module `tests` submodule, e.g.
`lib/src/modules/lnk/tests/`). Tests compile small rules importing `php` and
assert match/no-match against crafted buffers.

### Positive cases (expect `is_php == true`)
- `<?php echo 1;`
- `<?PHP ... ?>` (case-insensitive keyword)
- `<?= $x ?>` (short echo)
- GIF/JPEG-header polyglot: `GIF89a` magic bytes followed later by `<?php`.
- HTML with PHP buried mid-document: `<html>...<?php system($_GET['c']); ?>...`
- Short-tag webshell: `<? eval($_POST['x']); ?>` (bare `<?` + token).
- PHP tag preceded by leading whitespace / UTF-8 BOM.

### Negative cases (expect `is_php == false`)
- Plain text containing no `<?`.
- XML document beginning `<?xml version="1.0"?>` with no PHP.
- Binary blob containing incidental `<?` bytes but no nearby PHP token.
- HTML/JS that contains `<?` only as part of unrelated content without PHP
  tokens in the window.

### Edge cases
- Empty buffer ⇒ `is_php == false`.
- `<?` at the very end of the buffer with no following window ⇒ `false`.
- A bare `<?` followed by a PHP token just beyond the 256-byte window ⇒ `false`
  (documents the window boundary).

### Documentation fixtures
- Add a short module doc section (the `magic` module's doc style is a good
  template) covering `php.is_php` and the short-circuit usage guidance above.

## Rejected Alternatives

- **Wrap libmagic / reuse `magic` module.** `magic.mime_type() == "text/x-php"`
  already exists, but only inspects near the file start and misses appended /
  embedded / polyglot PHP — exactly the target case. A thin wrapper would add no
  detection capability.
- **Full parse with mago (Rust PHP parser).** Most rigorous on validity, but a
  heavy dependency, slower per scan, and requiring a clean parse **hurts recall**
  on the malformed/obfuscated webshells we most want to catch.
- **Go parsers (wudi/php-parser).** Out of process / FFI; unsuitable for an
  in-process Rust module.
- **Exposing AST-derived structure (eval/includes/function calls).** Useful but
  explicitly out of scope; this module is a single boolean by decision.

## Open Questions / Tunables (resolve during implementation)

- Final PHP token list and weak-signal window size (256 bytes is a starting
  proposal).
- Whether to treat additional XML processing instructions (`<?php-stash`-style
  edge cases) specially beyond `<?xml` (likely unnecessary).
