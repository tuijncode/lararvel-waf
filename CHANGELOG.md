# Changelog

All notable changes to `tuijncode/laravel-waf` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-07-08

### Added

- Decisive signatures: a `decisive` flag on custom patterns forces confidence to
  100 on a single match, so unambiguous probes are blocked outright regardless of
  `block_confidence`. The bundled `.env`, `.git`, `.svn`, credential-directory,
  SSH private key and server-config probes are now decisive.

### Fixed

- A bare `.env` / `.git/config` probe from an ordinary client no longer slips
  through in blocking mode. Previously a lone file-probe hit scored 37 (below the
  default block threshold of 60), because a single signature could never reach the
  threshold on the anomaly math alone.

## [1.0.0] - 2026-07-06

### Added

- OWASP Core Rule Set inspection engine covering SQL injection, XSS, RCE, LFI /
  directory traversal, RFI, SSRF, XXE, Log4Shell, NoSQL injection, PHP injection
  and command injection.
- Scanner, bot and rate-based flood detection.
- 0–100 confidence scoring with an anomaly score and categorical label.
- `waf_logs` storage and the `ThreatDetected` event for custom responses.
- Detection / blocking modes with a configurable block response (status,
  message, JSON, custom view, `Retry-After`) and a `RequestBlocked` event.
- Rule tuning: `paranoia_level`, `disabled_rules` and `disabled_categories`.
- A bundled signature pack (`config/waf-patterns.php`) of provider secrets,
  card numbers, sensitive files, framework/CVE probes, deserialization, SSTI,
  CRLF, open redirect and more — toggleable and mergeable with your own
  `custom_patterns`.
- Exclusion rules for accepted false positives (logged as `excluded`).
- Secret redaction: captured API keys, passwords and card numbers are masked
  before being written to `waf_logs`.
- Evasion-resistant surface normalisation: double URL-decode, HTML-entity decode
  and null-byte stripping.
- Correlation analytics (`CorrelationAnalyzer` + `waf:correlate`) for coordinated
  attacks, campaigns and rapid attackers.
- Boot-time configuration validation (logs warnings, never throws).
- Queue support for off-request logging.
- `waf:purge` (with an optional daily retention schedule), `waf:stats` and
  `waf:correlate` console commands.
- Typed value objects (`Signature`, `SignatureMatch`, `Detection`) throughout the
  engine.
