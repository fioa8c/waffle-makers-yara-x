---
title: "php"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "php-module"
weight: 850
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `php` module detects the presence of PHP code in the scanned data. It is
designed for webshell and polyglot hunting: it finds PHP open tags *anywhere*
in the buffer, including PHP that has been appended to or embedded inside files
that other tools classify as images, HTML, or generic data.

Detection is a lightweight heuristic over the whole buffer:

* `<?php` (case-insensitive) and `<?=` are treated as strong signals and mark
  the data as PHP wherever they appear.
* A bare `<?` is ambiguous (it is also how XML declarations begin), so it is
  only counted when it is not `<?xml` and a PHP token (a superglobal such as
  `$_POST`, or a function/keyword such as `eval`, `system`, or `base64_decode`)
  appears within the next 256 bytes. This catches short-tag webshells while
  suppressing XML and incidental binary data.

The module is recall-oriented: it favors catching evasive or obfuscated PHP over
proving that the data is syntactically valid PHP.

-------

## Module structure

| Field  | Type | Description                                          |
|--------|------|------------------------------------------------------|
| is_php | bool | True if PHP code is detected anywhere in the data.   |

-------

## Using `php.is_php` as a gate

YARA-X searches for patterns lazily: the search runs only the first time a rule
condition references a pattern. Because `php.is_php` is computed before
conditions are evaluated, you can place it first in a condition to skip the
pattern search entirely on non-PHP data:

```yara
import "php"

rule php_webshell {
    strings:
        $a = "eval($_POST"
        $b = "assert($_REQUEST"
    condition:
        php.is_php and ($a or $b)
}
```

When `php.is_php` is false, the `and` short-circuits and the patterns are never
searched. For this optimization to take effect, `php.is_php` must be the **first**
operand of the `and`. To gate every rule in a namespace at once, use a global
rule:

```yara
import "php"

global rule must_be_php {
    condition:
        php.is_php
}
```
