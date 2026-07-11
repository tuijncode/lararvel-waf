# Laravel WAF

[![Tests](https://github.com/tuijncode/laravel-waf/actions/workflows/tests.yml/badge.svg)](https://github.com/tuijncode/laravel-waf/actions/workflows/tests.yml)
[![Latest Version](https://img.shields.io/packagist/v/tuijncode/laravel-waf.svg)](https://packagist.org/packages/tuijncode/laravel-waf)
[![PHP Version](https://img.shields.io/packagist/php-v/tuijncode/laravel-waf.svg)](https://packagist.org/packages/tuijncode/laravel-waf)
[![License](https://img.shields.io/packagist/l/tuijncode/laravel-waf.svg)](LICENSE.txt)

A Web Application Firewall (WAF) for Laravel. It inspects every incoming request
against a signature set modelled on the [OWASP Core Rule Set](https://coreruleset.org/)
and logs — or blocks — anything that looks like an attack.

## Features

- **30+ detection patterns** — SQL injection, XSS, RCE, directory traversal / LFI,
  RFI, SSRF, XXE, Log4Shell, NoSQL injection, PHP injection and command injection,
  organised by OWASP CRS rule id and category.
- **Scanner detection** — SQLMap, Nikto, Nmap, Burp Suite, Acunetix, WPScan,
  Nessus, Nuclei, Metasploit and more, by their User-Agent fingerprint.
- **Bot detection** — scripting libraries, headless browsers and empty/spoofed
  user agents.
- **DDoS monitoring** — rate-based threshold detection over a configurable window.
- **Confidence scoring** — every threat gets a 0-100 score derived from the CRS
  anomaly score plus contextual signals (breadth, request location, scanner/bot/DoS).
- **Evasion-resistant** — surfaces are URL-decoded (twice), HTML-entity decoded
  and null-byte stripped before matching.
- **Secret redaction** — captured API keys, passwords and card numbers are masked
  before they reach `waf_logs`.
- **`waf_logs` storage** — detected threats are persisted for auditing.
- **`ThreatDetected` event** — hook in your own response (block, ban, notify, SIEM).
- **Exclusion rules** — suppress known false positives by rule id / label and path.
- **Correlation analytics** — detect coordinated / distributed campaigns across
  many IPs from the logs (`waf:correlate`).
- **Config validation** — misconfiguration is surfaced as a log warning at boot.
- **Queue support** — defer logging off the request cycle.
- **Retention** — prune old logs manually or on a daily schedule.

## Installation

```bash
composer require tuijncode/laravel-waf
```

Publish the config and migration, then migrate:

```bash
php artisan vendor:publish --tag=waf-config
php artisan vendor:publish --tag=waf-migrations
php artisan migrate
```

`waf-config` publishes both config files at once. To publish them separately:

```bash
php artisan vendor:publish --tag=waf-config-main # config/waf.php only
php artisan vendor:publish --tag=waf-config-patterns # config/waf-patterns.php only
```

## Usage

Apply the `waf` middleware globally (in `bootstrap/app.php` on Laravel 11+) or per
route group:

```php
Route::middleware('waf')->group(function () {
    // protected routes
});
```

By default the WAF runs in **detection** mode: it inspects and logs but never
interferes with the response. Set `WAF_MODE=blocking` to have it abort
high-confidence requests with a `403`.

> [!IMPORTANT]
> **Behind a proxy, CDN or load balancer?** Everything keys off
> `$request->ip()` — DDoS counting, the IP allowlist and the logged IP. If
> Laravel's [trusted proxies](https://laravel.com/docs/requests#configuring-trusted-proxies)
> aren't configured, that resolves to the *proxy's* address, so flood detection
> and allowlisting silently misbehave and every finding shows the same IP.
> Configure `TrustProxies` (or `$middleware->trustProxies(...)` on Laravel 11+)
> so the real client IP is used.

### Responding to threats

Every logged threat dispatches `Tuijncode\LaravelWaf\Events\ThreatDetected`.
Implement your own response by listening for it:

```php
use Tuijncode\LaravelWaf\Events\ThreatDetected;

Event::listen(function (ThreatDetected $event) {
    // $event->log        — the row written to waf_logs
    // $event->result     — the full InspectionResult
    // $event->ipAddress  — the offending IP

    if ($event->result->confidenceScore() >= 80) {
        // e.g. ban the IP, page on-call, push to your SIEM ...
    }
});
```

## Configuration

Key options in `config/waf.php`:

| Option                 | Default     | Description                                                |
|------------------------|-------------|------------------------------------------------------------|
| `mode`                 | `detection` | `detection` (log only) or `blocking`.                      |
| `min_confidence`       | `10`        | Threats below this 0-100 score are ignored.                |
| `block_confidence`     | `60`        | In blocking mode, refuse requests at/above this score.     |
| `paranoia_level`       | `2`         | `1` = high-confidence rules only; `2` adds broader rules.  |
| `disabled_rules`       | `[]`        | Rule ids to silence, e.g. `['930100']`.                    |
| `disabled_categories`  | `[]`        | Categories to silence, e.g. `['nosqli']`.                  |
| `skip_paths`           | assets, …   | Wildcard paths excluded from inspection.                   |
| `only_paths`           | `[]`        | If set, ONLY these paths are inspected.                    |
| `whitelisted_ips`      | `[]`        | CIDR-aware IP allowlist.                                    |
| `ddos.threshold`       | `300`       | Requests per `ddos.window` seconds before a DoS flag.      |

> DDoS monitoring is built on Laravel's rate limiter, so it works with any
> configured cache store.

### Blocking & the block response

In `blocking` mode, a request whose confidence reaches `block_confidence` is
refused. The response is configurable (`config/waf.php` → `block_response`):
custom status/message, a Blade `view`, automatic JSON for API clients (or
`always_json`), and a `Retry-After` header on rate-based blocks. A
`Tuijncode\LaravelWaf\Events\RequestBlocked` event fires on every block so you
can ban the IP or record a metric:

```php
use Tuijncode\LaravelWaf\Events\RequestBlocked;

Event::listen(function (RequestBlocked $event) {
    Firewall::ban($event->request->ip()); // your own logic
});
```

### Tuning out false positives

Three levers, cheapest first:

- **`paranoia_level`** — drop to `1` to run only the highest-confidence rules.
- **`disabled_rules` / `disabled_categories`** — silence a specific noisy rule
  or a whole category pre-emptively.
- **Exclusion rules** — accept a specific finding on a specific path (below).

### Exclusion rules (false positives)

Suppress a noisy detection by inserting a row into `waf_exclusion_rules`, or
build one from a threat you already logged:

```php
use Tuijncode\LaravelWaf\Services\ExclusionRuleService;

app(ExclusionRuleService::class)->acceptFromLog(
    logId: $wafLogId,
    userId: auth()->id(),
    reason: 'Legitimate content in the CMS editor',
);
```

A threat is suppressed when its `type` contains the rule's `pattern_label`
(e.g. a rule id like `941130`) and its path matches the optional
`path_pattern` (wildcards supported; leave empty to match any path).

Excluded threats are still written to `waf_logs` with `action_taken = 'excluded'`
(for auditing) but are never blocked.

### Custom patterns

Detection draws on three layers, in order of precedence:

1. The built-in **OWASP core rules** (`Tuijncode\LaravelWaf\Rules\CoreRuleSet`).
2. The **default pattern pack** in `config/waf-patterns.php` (toggle with
   `WAF_PATTERN_PACK`).
3. Your **own signatures** in `config/waf.php` under `custom_patterns` — these
   win on a regex collision with the pack.

Add your own in `config/waf.php`:

```php
'custom_patterns' => [
    // Simple: regex => label (uses the default custom severity)
    '/\bmy-secret-token\b/i' => 'Internal Token Leak',

    // Full control over severity and which request parts to scan
    '/forbidden/i' => [
        'label'    => 'Forbidden Keyword',
        'severity' => 'critical',                 // critical|error|warning|notice
        'targets'  => ['query', 'body'],
    ],
],
```

Matches are logged under the `custom` category with rule ids `CUSTOM-1`,
`CUSTOM-2`, … Invalid patterns are logged once and skipped.

A larger, ready-made **signature pack** ships separately in
`config/waf-patterns.php` and is merged in automatically:

- **Secrets & API keys** — AWS, Google, Slack, GitHub / GitLab, Stripe, Twilio,
  SendGrid, npm, DigitalOcean, AI providers, private-key material and JWTs.
- **Payment card data (PCI)** — Visa / Mastercard / Amex / Discover PANs.
- **Sensitive files** — `.env`, `.git`, `.ssh`, `id_rsa`, `wp-config.php`,
  backup/archive artefacts.
- **Endpoint probing** — phpMyAdmin, WordPress, Spring Actuator, Apache status.
- **Framework / CVE probes** — Laravel Ignition RCE, PHPUnit eval-stdin,
  Spring4Shell, OGNL / Struts, server-side includes, prototype pollution.
- **Insecure deserialization** — Java and .NET payload markers.
- **SSTI / XSS / SQLi variants**, CRLF header injection, open redirect,
  GraphQL introspection, web shells, reverse shells and crypto miners.

Credential signatures are scoped to the URL / query string (not request bodies),
so normal login POSTs and `Authorization: Bearer …` headers don't trip them.
Publish the file to customise, or turn the pack off entirely with
`WAF_PATTERN_PACK=false`. On a regex collision, your own pattern wins.

### Queue support

Set `WAF_QUEUE=true` to dispatch the `waf_logs` insert to a queue instead of
writing it inline. The `ThreatDetected` event still fires synchronously, so
blocking decisions remain immediate.

### Correlation analytics

Some attacks only show up in aggregate. `CorrelationAnalyzer` mines `waf_logs`
for distributed activity — one target hit from many IPs, one attack class
spreading across the fleet, or a single IP hammering many endpoints:

```php
use Tuijncode\LaravelWaf\Services\CorrelationAnalyzer;

$analyzer = app(CorrelationAnalyzer::class);
$analyzer->coordinatedAttacks(windowMinutes: 15, minIps: 3);
$analyzer->campaigns(windowHours: 24, minIps: 5);
$analyzer->rapidAttackers(windowMinutes: 5, minHits: 10);
$analyzer->summary(); // ['coordinated_attacks' => …, 'campaigns' => …, 'rapid_attackers' => …]
```

### Console commands

```bash
php artisan waf:stats --days=7    # summary: counts by category / severity / IP
php artisan waf:correlate         # surface coordinated / distributed attacks
php artisan waf:purge --days=90   # delete findings older than N days
```

Set `WAF_RETENTION=true` (and `WAF_RETENTION_DAYS`) to run the purge
automatically every day at 02:00 via Laravel's scheduler.

### Configuration validation

At boot the package checks your config and logs a warning (never throws) for
anything invalid — a bad `mode`, an out-of-range `paranoia_level`, a severity
typo, an unknown `disabled_categories` entry. Warnings are throttled to once an
hour per problem set. Disable with `WAF_VALIDATE_CONFIG=false`.

## Testing & quality

```bash
composer test         # Pest suite
composer test:style   # Pint (code style, --test)
composer test:types   # PHPStan / Larastan static analysis
```

The suite drives real requests through the middleware and asserts on the logged
finding. Among the cases it covers are the canonical attacks:

| Attack              | Example request                              |
|---------------------|----------------------------------------------|
| SQL injection       | `/?q=' UNION SELECT * FROM users--`          |
| XSS                 | `/?q=<script>alert(1)</script>`              |
| Directory traversal | `/?file=../../etc/passwd`                    |
| RCE                 | `/?cmd=system('ls -la')`                     |

CI runs the suite across PHP 8.2–8.5 and Laravel 10–13.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
