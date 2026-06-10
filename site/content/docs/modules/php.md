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

* `<?php` (case-insensitive, and only when followed by a non-identifier
  character) is the one signal that stands on its own. This five-byte sequence
  does not occur by chance in binary data, so it marks the data as PHP wherever
  it appears.
* A short tag — a bare `<?` or the echo tag `<?=` — is ambiguous: those few
  bytes occur constantly in binary data such as image pixels and compressed
  streams. A short tag is therefore only counted when a PHP token appears within
  the next 256 bytes: a superglobal such as `$_POST`, or a function/keyword such
  as `eval`, `system`, or `base64_decode`. Tokens are matched at identifier word
  boundaries, so `print` inside `printOutput` does not count.
* XML processing instructions (`<?xml` and `<?xpacket`, the latter common in the
  XMP metadata embedded in images) are never treated as PHP.

The module is recall-oriented for genuine PHP code while avoiding the false
positives that short tags would otherwise cause on binary files. It does not try
to prove that the data is syntactically valid PHP.

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
