# Security Policy

## Supported versions

The latest released `1.x` line receives security fixes.

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately by email to **davidvandertuijn@mac.com**, or
via GitHub's [private security advisory](https://github.com/tuijncode/laravel-waf/security/advisories/new)
form. Include:

- a description of the issue and its impact,
- steps to reproduce (a failing test or request is ideal),
- affected version(s).

You can expect an acknowledgement within a few days. Once a fix is ready it will
be released and the reporter credited (unless anonymity is requested).

## Scope note

This package is a defence-in-depth layer, not a replacement for secure coding
(parameterised queries, output encoding, authorisation checks, validated input).
A signature-based WAF reduces exposure and buys time; it cannot guarantee an
insecure application is safe. Reports of bypasses that lead to missed detections
are welcome and treated as security issues.
