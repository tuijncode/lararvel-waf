<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Enable the WAF
    |--------------------------------------------------------------------------
    |
    | Globally enable or disable request inspection.
    |
    */
    'enabled' => env('WAF_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Validate Configuration
    |--------------------------------------------------------------------------
    |
    | When enabled, the package checks this config at boot and logs a warning
    | for anything invalid (bad mode, out-of-range paranoia level, severity
    | typo, unknown disabled category …). It never throws.
    |
    */
    'validate_config' => env('WAF_VALIDATE_CONFIG', true),

    /*
    |--------------------------------------------------------------------------
    | Enabled Environments
    |--------------------------------------------------------------------------
    |
    | Restrict inspection to specific environments. Set to null or an empty
    | array to run in every environment.
    |
    */
    'enabled_environments' => null,

    /*
    |--------------------------------------------------------------------------
    | Operating Mode
    |--------------------------------------------------------------------------
    |
    | 'detection' — inspect and log, never interfere with the response.
    | 'blocking'  — additionally abort offending requests with a 403 once the
    |               confidence score reaches `block_confidence`.
    |
    */
    'mode' => env('WAF_MODE', 'detection'),

    /*
    |--------------------------------------------------------------------------
    | Error Handling
    |--------------------------------------------------------------------------
    |
    | What happens to a request when inspection itself throws (cache store
    | down, malformed request, ...).
    |
    | 'open'   — let the request through (availability first, the default).
    | 'closed' — refuse the request with a 503 (security first; consider this
    |            when running blocking mode).
    |
    */
    'on_error' => env('WAF_ON_ERROR', 'open'),

    /*
    |--------------------------------------------------------------------------
    | Database Table
    |--------------------------------------------------------------------------
    |
    | Where detected threats are stored.
    |
    */
    'table_name' => env('WAF_TABLE', 'waf_logs'),

    /*
    |--------------------------------------------------------------------------
    | Confidence Thresholds
    |--------------------------------------------------------------------------
    |
    | min_confidence   — threats below this 0-100 score are ignored entirely
    |                    and never written to `waf_logs`.
    | block_confidence — in blocking mode, requests at or above this score are
    |                    refused.
    |
    */
    'min_confidence' => env('WAF_MIN_CONFIDENCE', 10),
    'block_confidence' => env('WAF_BLOCK_CONFIDENCE', 60),

    /*
    |--------------------------------------------------------------------------
    | Block Response
    |--------------------------------------------------------------------------
    |
    | The response returned to a blocked client (blocking mode only). JSON is
    | sent automatically to clients that expect it; set `always_json` to force
    | it. Point `view` at a Blade view for a branded block page. Rate-based
    | blocks additionally carry a `Retry-After` header (see the `ddos.window`).
    |
    */
    'block_response' => [
        'status' => env('WAF_BLOCK_STATUS', 403),
        'message' => env('WAF_BLOCK_MESSAGE', 'Forbidden'),
        'view' => env('WAF_BLOCK_VIEW', null),
        'always_json' => env('WAF_BLOCK_JSON', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Rule Tuning
    |--------------------------------------------------------------------------
    |
    | paranoia_level      — 1 runs only the highest-confidence signatures
    |                       (fewest false positives); 2 (default) adds the
    |                       broader rules. Custom patterns default to level 1
    |                       (override per-pattern, or via custom_pattern_paranoia).
    | disabled_rules      — rule ids to silence entirely, e.g. ['930100'].
    | disabled_categories — whole categories to silence, e.g. ['nosqli'].
    |
    */
    'paranoia_level' => env('WAF_PARANOIA', 2),
    'disabled_rules' => [],
    'disabled_categories' => [],

    /*
    |--------------------------------------------------------------------------
    | Duplicate Suppression
    |--------------------------------------------------------------------------
    |
    | Identical threats from the same IP are only logged once within this many
    | minutes to avoid flooding the log table.
    |
    | dedup_include_path — by default the key is IP + signature, so the same
    | attack aimed at many endpoints collapses to one finding. Enable this to
    | add the path to the key (one finding per path), which keeps the breadth
    | of a sweep visible to the correlation analytics at the cost of more rows.
    | dedup_flush_seconds — a duplicate bumps the finding's `hit_count` instead
    | of being dropped. To keep that off the database on a route under attack,
    | the bumps are accumulated in the cache and written back at most once per
    | this many seconds (so the count is eventually consistent). Set to 0 to
    | write every bump straight through (exact, but one UPDATE per duplicate).
    |
    */
    'dedup_minutes' => env('WAF_DEDUP_MINUTES', 5),
    'dedup_include_path' => env('WAF_DEDUP_INCLUDE_PATH', false),
    'dedup_flush_seconds' => env('WAF_DEDUP_FLUSH_SECONDS', 10),

    /*
    |--------------------------------------------------------------------------
    | Secret Redaction
    |--------------------------------------------------------------------------
    |
    | The WAF detects secrets (API keys, passwords, tokens, card numbers). To
    | avoid storing them verbatim in `waf_logs`, the captured value of any
    | finding whose label matches one of `labels` is masked before it is
    | written to the URL and payload columns.
    |
    */
    'redact' => [
        'enabled' => env('WAF_REDACT', true),
        'labels' => [
            'key', 'token', 'secret', 'password', 'credential',
            'card', 'private key', 'session id', 'jwt', 'oauth', 'bearer',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Path Filtering
    |--------------------------------------------------------------------------
    |
    | only_paths — if non-empty, ONLY these (wildcard) paths are inspected.
    | skip_paths — paths excluded from inspection (assets, health checks …).
    |
    | NOTE: Livewire's asset routes are skipped, but its update endpoint
    | (`livewire/update`) is deliberately NOT — it carries user input worth
    | inspecting. Add `livewire/*` to skip_paths if that proves too noisy.
    |
    */
    'only_paths' => [
        // 'admin/*',
        // 'api/*',
    ],

    'skip_paths' => [
        'assets/*',
        'images/*',
        'css/*',
        'js/*',
        'build/*',
        'favicon.ico',
        'health',
        'up',
        'telescope/*',
        'horizon/*',
        '_debugbar/*',
        'livewire/livewire.js',
        'livewire/livewire.min.js*',
    ],

    /*
    |--------------------------------------------------------------------------
    | Whitelisted IPs
    |--------------------------------------------------------------------------
    |
    | Requests from these IPs (CIDR supported) skip inspection entirely.
    |
    */
    'whitelisted_ips' => array_values(array_filter(explode(',', (string) env('WAF_WHITELISTED_IPS', '')))),

    /*
    |--------------------------------------------------------------------------
    | Whitelisted User-Agents
    |--------------------------------------------------------------------------
    |
    | Trusted automated clients (case-insensitive substring match) that are
    | exempt from bot detection — e.g. a known uptime monitor or health-check
    | probe that would otherwise be logged every window. Signature, scanner and
    | flood detection still apply; only the "bot" signal is suppressed.
    |
    */
    'whitelisted_agents' => array_values(array_filter(explode(',', (string) env('WAF_WHITELISTED_AGENTS', '')))),

    /*
    |--------------------------------------------------------------------------
    | DDoS Monitoring
    |--------------------------------------------------------------------------
    |
    | Volumetric abuse detection, powered by the framework rate limiter. More
    | than `threshold` requests from one client inside a `window`-second span
    | raises the flood signal.
    |
    | Only inspected requests count towards the budget: traffic to `skip_paths`
    | (assets, health checks) and from whitelisted IPs is not tallied.
    |
    | block — a flood scores below `block_confidence` by design, so in blocking
    | mode it is logged but not refused unless you opt in here. When enabled,
    | an over-budget client is refused (with a `Retry-After` header) on the
    | flood signal alone.
    |
    */
    'ddos' => [
        'enabled' => env('WAF_DDOS_ENABLED', true),
        'block' => env('WAF_DDOS_BLOCK', false),
        'threshold' => env('WAF_DDOS_THRESHOLD', 300),
        'window' => env('WAF_DDOS_WINDOW', 60),
    ],

    /*
    |--------------------------------------------------------------------------
    | Auto-Ban (blocking mode)
    |--------------------------------------------------------------------------
    |
    | Temporarily ban a client that keeps getting blocked: after `max_blocks`
    | blocked requests inside a rolling `window` (seconds), the IP is refused
    | up front for `duration` seconds — without running the full inspection
    | pipeline on every request. Bans live in the cache and expire on their
    | own. Only applies in blocking mode (strikes are counted per block).
    |
    */
    'auto_ban' => [
        'enabled' => env('WAF_AUTO_BAN', false),
        'max_blocks' => env('WAF_AUTO_BAN_MAX_BLOCKS', 5),
        'window' => env('WAF_AUTO_BAN_WINDOW', 300),
        'duration' => env('WAF_AUTO_BAN_DURATION', 3600),
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Patterns
    |--------------------------------------------------------------------------
    |
    | Extend the OWASP Core Rule Set with your own signatures. Keyed by regex.
    | Two value formats are supported:
    |
    |   '/regex/i' => 'My Label',                              // simple
    |   '/regex/i' => [                                        // full control
    |       'label'     => 'My Label',
    |       'severity'  => 'critical',                         // critical|error|warning|notice
    |       'targets'   => ['query', 'body', 'path', 'headers', 'cookie'],
    |       'validator' => 'luhn',                             // optional post-match check
    |   ],
    |
    | Invalid patterns are logged once and skipped. Matches are stored under the
    | `custom` category with rule ids CUSTOM-1, CUSTOM-2, …
    |
    | This array is for YOUR OWN patterns. A large, ready-made signature pack
    | (provider secrets, credential leaks, web shells, …) ships separately in
    | `config/waf-patterns.php` and is merged in automatically.
    |
    */
    'custom_patterns' => [
        // '/\bmy-secret-token\b/i' => 'Internal Token Leak',
    ],

    /*
    |--------------------------------------------------------------------------
    | Default Pattern Pack
    |--------------------------------------------------------------------------
    |
    | Toggle the bundled signature pack in `config/waf-patterns.php`. Disable it
    | if you only want the OWASP core rules plus your own `custom_patterns`.
    |
    */
    'pattern_pack' => env('WAF_PATTERN_PACK', true),

    'custom_pattern_severity' => env('WAF_CUSTOM_SEVERITY', 'error'),
    'custom_pattern_paranoia' => env('WAF_CUSTOM_PARANOIA', 1),

    /*
    |--------------------------------------------------------------------------
    | Queue Support
    |--------------------------------------------------------------------------
    |
    | When enabled, the `waf_logs` insert is dispatched to a queue instead of
    | running inline, keeping logging off the request cycle. The ThreatDetected
    | event still fires synchronously so blocking decisions are immediate.
    |
    */
    'queue' => [
        'enabled' => env('WAF_QUEUE', false),
        'connection' => env('WAF_QUEUE_CONNECTION', null),
        'queue' => env('WAF_QUEUE_NAME', 'default'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Retention (Auto-Purge)
    |--------------------------------------------------------------------------
    |
    | Automatically delete logs older than `days` on a daily schedule (requires
    | Laravel's scheduler / cron). You can always run it manually:
    |
    |   php artisan waf:purge --days=90
    |
    */
    'retention' => [
        'enabled' => env('WAF_RETENTION', false),
        'days' => env('WAF_RETENTION_DAYS', 90),
    ],

];
