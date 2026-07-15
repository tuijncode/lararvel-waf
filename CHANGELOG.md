# Changelog

All notable changes to `tuijncode/laravel-waf` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-07-15

### Added

- Auto-ban: with `WAF_AUTO_BAN=true` (blocking mode), an IP that earns
  `auto_ban.max_blocks` blocks inside a rolling `auto_ban.window` is refused up
  front for `auto_ban.duration` seconds — without running the inspection
  pipeline on every request. Bans are cache-based and expire on their own;
  banned responses carry a `Retry-After` header. A `IpBanned` event fires when
  a ban is applied, `AutoBanManager::lift()` and `php artisan waf:unban {ip}`
  clear one early.
- Fail-open / fail-closed choice: `WAF_ON_ERROR=closed` refuses requests with a
  `503` when inspection itself throws, instead of the default fail-open.
- The client names of uploaded files are now inspected on the `body` surface,
  so a `c99.php`-style web shell upload is caught by name. The binary content
  itself is never scanned.
- Named post-match validators for signatures: a signature can name a `validator`
  (built-in: `luhn`) that a regex hit must also pass. The bundled card-number
  rule now Luhn-validates, so ordinary 16-digit values (order ids, tracking
  numbers) are no longer flagged as a PAN.
- User-Agent allowlist (`whitelisted_agents`): trusted automated clients (e.g. a
  known uptime monitor) are exempt from bot detection, while signature, scanner
  and flood detection still apply.
- `ddos.block` toggle: a flood scores below `block_confidence` by design, so in
  blocking mode it was logged but never refused. Enable `ddos.block` (or
  `WAF_DDOS_BLOCK=true`) to refuse an over-budget client on the flood signal
  alone, with a `Retry-After` header.
- `hit_count` column on `waf_logs`: a duplicate collapsed by the dedup window
  now bumps the existing finding's counter instead of being dropped, so the
  true request volume stays on the record. The correlation analytics sum it, so
  `waf:correlate`'s rapid-attacker detection sees a single-signature flood that
  row-counting previously missed. (Under queueing the row id isn't known
  synchronously, so duplicates there aren't tallied.) To keep this off the
  database on a route under attack, the bumps are accumulated in the cache and
  written back at most once per `dedup_flush_seconds` (default 10; set to 0 for
  an exact, write-per-duplicate count) — so the stored count is eventually
  consistent rather than costing one UPDATE per request.
- `RequestBlocked` is throttled to once per IP + signature per dedup window
  (matching how often the finding is logged), so a flood — especially with
  `ddos.block` on — can't drown a listener in duplicate block events. The
  auto-ban strike still counts every blocked request, so a ban is still earned
  quickly.
- Every finding carries an `event_id` (UUID) column, also passed on the
  `ThreatDetected` event, so a listener can reference the stored row even when
  the insert is queued.
- Read-side `WafLog` Eloquent model, `Prunable` for retention via Laravel's
  `model:prune`.
- `dedup_include_path`: fold the request path into the dedup key so the same
  attack across many endpoints stays visible to the correlation analytics
  instead of collapsing into one finding.
- Config validation now also covers `custom_patterns` and the pattern pack (the
  regex must compile, severities/target surfaces/validators must be known — a
  typo like `targets: ['querry']` previously made a pattern silently dead), plus
  `enabled_environments` and the new `on_error` / `auto_ban` options.
- The `waf_logs` migration indexes `created_at`; purge, stats and correlation
  analytics all filter on it, against a table that grows fastest under attack.
- Upgrade migration (`waf-migrations-upgrade` publish tag) that adds the
  `event_id` and `hit_count` columns and the `created_at` index to an existing
  `waf_logs` table. Idempotent, so it is safe on a table that already has them.

### Fixed

- `$`-anchored pack patterns (the `.env`, `.git` and `.svn` probes and the
  backup/archive probe) missed hits at the end of a query parameter: inspected
  surfaces are newline-joined decode variants, and without `/m` the `$` anchor
  only matches at the very end of the joined string. Most notably the decisive
  `.env` rule did not fire on `?file=.env`. These patterns now carry `/m`.
- The Sensitive Artefact Probe (`.bash_history`, `.zsh_history`, `.DS_Store`)
  never matched a real probe: a leading `\b` before the literal dot required a
  word boundary that `/.DS_Store` doesn't have. The boundary is removed.
- The `web.config` probe missed the query-value variant — a `^` anchor without
  `/m`, the same class of bug as the `$` anchors. It now carries `/m` and a
  wider set of leading delimiters.
- Bot-only findings were never recorded under the default configuration: a
  lone bot signal scored 8, below the default `min_confidence` of 10. It now
  scores 12, so scripted clients (curl, python-requests, headless browsers)
  actually show up in `waf_logs`.
- Payloads larger than the 16 KB per-surface cap are now sampled head + tail
  instead of hard-truncated, so prepending 16 KB of padding can no longer push
  an attack out of the inspected window.
- Catastrophic regex cost on floods: the SSTI object-access, Ruby-interpolation,
  CRLF-injection and obfuscated-Log4Shell signatures used unbounded spans that
  turn quadratic on a long `{{{{…`, `#{#{…` or `\r\n\r\n…` run (a crafted
  request could pin a worker for minutes). Spans are bounded, the SSTI and Ruby
  rules only start at the first delimiter of a run, and the CRLF rule no longer
  lets `\s*` swallow further line breaks. `PerformanceTest` now covers all of
  these flood shapes.
- `Waf::inspect()` is now truly read-only: it no longer advances the flood
  counter, which double-counted DDoS hits when the facade was used alongside
  the middleware. Counting moved to `handle()`; `DdosMonitor::tripped()` is a
  pure check and the new `DdosMonitor::hit()` registers a request.
- Captured match values are no longer truncated at 200 characters, which left
  the tail of a long secret (e.g. a JWT) unmasked in the stored URL and
  payload. The capture cap is now 1024 characters.
- Exclusion rules with a `match_label` shorter than 3 characters are ignored:
  the label is matched as a substring, so `"94"` would silently suppress every
  `94x`-family rule.
- `DdosMonitor` constructor arguments were dead — the merged config always
  overrode them. Explicit arguments now win over the config.
- `CorrelationAnalyzer::rapidAttackers()` under-counted: it ran `COUNT(*)` per
  IP, but the 5-minute dedup window collapsed a burst of one attack into a
  single row, so a high-volume single-signature flood scored 1 and slipped past
  the threshold. It now sums `hit_count`.

### Changed

- Livewire's asset routes are still skipped, but its `livewire/update` endpoint
  is now inspected by default — it carries user input worth checking. Add
  `livewire/*` back to `skip_paths` if that proves too noisy.
- `CoreRuleSet::rules()` is built once per process instead of building ~40
  signature objects on every request (relevant under Octane).

## [1.0.2] - 2026-07-11

### Fixed

- The exclusion allow-list no longer silently disables the WAF under Laravel's
  restricted cache deserialization. `ExclusionRuleService` cached the active
  rules as an `Illuminate\Support\Collection`, but cache stores unserialize with
  an `allowed_classes` restriction (`cache.serializable_classes`, which defaults
  to `false` in Laravel 12+), so on every cache hit the value came back as
  `__PHP_Incomplete_Class`. `active()` then threw a `TypeError`, `WafMiddleware`
  caught it and failed open — letting every request through, including probes
  that would otherwise be blocked. The active set is now cached as plain arrays
  and the objects are rebuilt on read, so no host-application config change is
  needed.

### Changed

- The config publish tag `waf-config` still publishes both config files, and each
  file can now be published on its own: `waf-config-main` for `config/waf.php` and
  `waf-config-patterns` for `config/waf-patterns.php`.

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
