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
fn detect_php(_data: &[u8]) -> bool {
    // Implemented incrementally in later tasks.
    false
}

#[cfg(test)]
mod tests {
    use crate::tests::rule_false;
    use crate::tests::test_rule;

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
