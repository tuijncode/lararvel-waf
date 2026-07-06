# Contributing

Thanks for helping improve `tuijncode/laravel-waf`.

## Getting started

```bash
git clone https://github.com/tuijncode/laravel-waf
cd laravel-waf
composer install
```

## Before you open a pull request

Run the full quality gate — CI runs the same three checks:

```bash
composer test         # Pest test suite
composer test:style   # Pint (code style)
composer test:types   # PHPStan / Larastan static analysis
```

`composer lint` applies the Pint fixes for you.

## Guidelines

- **Add a test** for every change. Detection changes belong in `tests/Feature`
  (drive a real request through the middleware and assert on the logged
  finding); pure logic belongs in `tests/Unit`.
- **Keep false positives out.** New signatures must not fire on ordinary
  traffic — the "clean request" tests are your guardrail. Scope a rule to the
  request surfaces it needs (`targets`) and pick a sensible `paranoia` level.
- **Match the surrounding style.** Value objects for structured data, readonly
  where possible, no `declare(strict_types)` (Pint enforces the rest).
- **Update the docs** — the README and `CHANGELOG.md` (Unreleased section) when
  behaviour or configuration changes.

## Adding a detection signature

- **A core OWASP-style rule** → add it to the relevant category method in
  `src/Rules/CoreRuleSet.php` with a unique CRS-style id, and classify it in
  `BROAD_RULE_IDS` if it trades precision for breadth (paranoia level 2).
- **A curated extra** → add it to `config/waf-patterns.php`.
- Always include a test proving it fires, and confirm the clean-request tests
  still pass.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — please don't file public issues for
vulnerabilities.
