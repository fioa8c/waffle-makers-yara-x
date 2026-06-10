/*! YARA module that detects the presence of PHP code.

This module exposes a single field, `php.is_php`, which is true when PHP
code is found anywhere in the scanned data. It is designed for webshell and
polyglot detection, where PHP may be appended to or embedded inside files
that other tools classify as images, HTML, or generic data.
*/
use crate::mods::prelude::*;
use crate::modules::protos::php::*;

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
    // Strong: `<?php` (keyword is case-insensitive).
    if after.len() >= 3 && after[..3].eq_ignore_ascii_case(b"php") {
        return true;
    }
    // Weak-signal handling is added in Task 3.
    false
}

#[cfg(test)]
mod tests {
    use super::detect_php;
    use crate::tests::rule_false;
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
}

register_module!("php", Php, main);
