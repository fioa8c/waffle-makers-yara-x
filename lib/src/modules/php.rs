/*! YARA module that detects the presence of PHP code.

This module exposes a single field, `php.is_php`, which is true when PHP
code is found anywhere in the scanned data. It is designed for webshell and
polyglot detection, where PHP may be appended to or embedded inside files
that other tools classify as images, HTML, or generic data.
*/
use crate::mods::prelude::*;
use crate::modules::protos::php::*;

/// Maximum number of bytes searched after a bare `<?` for a PHP token.
const WEAK_WINDOW: usize = 256;

fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Php, ModuleError> {
    let mut php = Php::new();
    php.is_php = Some(detect_php(data));
    Ok(php)
}

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
    // Strong: `<?php` open tag (keyword is case-insensitive). The keyword
    // must be followed by a non-identifier byte or end-of-buffer, otherwise
    // it is `<?phpsomething` which is not a PHP open tag.
    if after.len() >= 3
        && after[..3].eq_ignore_ascii_case(b"php")
        && after.get(3).is_none_or(|&b| !b.is_ascii_alphanumeric() && b != b'_')
    {
        return true;
    }
    // `<?xml` is an XML declaration / processing instruction, not PHP.
    if after.len() >= 3 && after[..3].eq_ignore_ascii_case(b"xml") {
        return false;
    }
    // Weak: a bare `<?` counts only if a PHP token appears within the window.
    let end = after.len().min(WEAK_WINDOW);
    window_has_php_token(&after[..end])
}

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

#[cfg(test)]
mod tests {
    use super::detect_php;
    use crate::tests::rule_false;
    use crate::tests::rule_true;
    use crate::tests::test_rule;

    #[test]
    fn strong_signals() {
        assert!(detect_php(b"<?php echo 1;"));
        assert!(detect_php(b"<?PHP echo 1;")); // case-insensitive keyword
        assert!(detect_php(b"<?= $x ?>")); // short echo tag
        assert!(detect_php(
            b"GIF89a....\x00<?php system($_GET['c']);"
        )); // polyglot
        assert!(detect_php(
            b"<html><body><?php phpinfo(); ?></body></html>"
        )); // embedded
        assert!(!detect_php(b"")); // empty
        assert!(!detect_php(b"plain text, no markers")); // no tag
        assert!(!detect_php(b"<?phpx not_a_tag")); // <?phpX is not a valid open tag
    }

    #[test]
    fn weak_signal_short_tag() {
        // Short-tag webshell: bare `<?` + PHP token within the window.
        assert!(detect_php(b"<? eval($_POST['x']); ?>"));
        assert!(detect_php(b"<? system($_GET['c']); ?>"));
        // Uppercase function name is still PHP (case-insensitive tokens).
        assert!(detect_php(b"<? EVAL($_POST['x']); ?>"));
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
}

register_module!("php", Php, main);
