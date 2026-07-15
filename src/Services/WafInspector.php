<?php

namespace Tuijncode\LaravelWaf\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Tuijncode\LaravelWaf\Events\ThreatDetected;
use Tuijncode\LaravelWaf\Jobs\StoreWafLog;
use Tuijncode\LaravelWaf\Rules\CoreRuleSet;
use Tuijncode\LaravelWaf\Rules\Signature;
use Tuijncode\LaravelWaf\Rules\SignatureMatch;

/**
 * Request inspection engine.
 *
 * Pulls apart an incoming request into inspectable surfaces, runs them past the
 * OWASP-style signature set (plus scanner, bot and flood signals), scores the
 * outcome and — when it clears the threshold — records a finding and announces
 * it through the ThreatDetected event for the host application to act on.
 */
class WafInspector
{
    /** Hard cap on bytes examined per surface, so a huge payload can't stall a regex. */
    private const SURFACE_LIMIT = 16000;

    /** Bytes kept from the end of an oversized surface, so padding can't push an attack out of view. */
    private const SURFACE_TAIL = 4000;

    private const SEVERITIES = ['critical', 'error', 'warning', 'notice'];

    public function __construct(
        private ?ConfidenceScorer $scorer = null,
        private ?ScannerDetector $scanners = null,
        private ?BotDetector $bots = null,
        private ?DdosMonitor $flood = null,
        private ?ExclusionRuleService $exclusions = null,
        private ?Redactor $redactor = null,
    ) {
        $this->scorer ??= new ConfidenceScorer;
        $this->scanners ??= new ScannerDetector;
        $this->bots ??= new BotDetector;
        $this->flood ??= new DdosMonitor;
        $this->exclusions ??= new ExclusionRuleService;
        $this->redactor ??= new Redactor;
    }

    /**
     * Evaluate a request. This is read-only: nothing is stored, dispatched or
     * counted — the flood counter is only advanced by handle().
     */
    public function inspect(Request $request): InspectionResult
    {
        $surfaces = $this->collectSurfaces($request);
        $hits = $this->scan($surfaces);

        $agent = (string) ($request->userAgent() ?? '');
        $scanner = $this->scanners->detect($agent);
        // A whitelisted agent (e.g. a known uptime monitor) is exempt from bot
        // detection, so a legitimate curl health check isn't logged every window.
        $bot = ($scanner || $this->isWhitelistedAgent($agent)) ? null : $this->bots->detect($agent);
        $flooding = config('waf.ddos.enabled', true)
            && $this->flood->tripped((string) $request->ip());

        if ($scanner !== null) {
            $hits[] = new SignatureMatch(
                id: '913100',
                category: 'scanner',
                name: 'Scanner',
                description: "Security scanner detected: {$scanner->name}",
                severity: $scanner->severity,
                context: 'user-agent',
                matched: $agent,
            );
        }

        return new InspectionResult(
            matches: $hits,
            isScanner: $scanner !== null,
            scannerName: $scanner?->name,
            isBot: $bot !== null,
            botName: $bot?->name,
            isDdos: $flooding,
            confidence: $this->scorer->calculate($hits, $scanner !== null, $bot !== null, $flooding),
        );
    }

    /**
     * Whether the agent is on the operator's allowlist of trusted automated
     * clients (case-insensitive substring match).
     */
    private function isWhitelistedAgent(string $agent): bool
    {
        if ($agent === '') {
            return false;
        }

        foreach ((array) config('waf.whitelisted_agents', []) as $needle) {
            $needle = (string) $needle;
            if ($needle !== '' && stripos($agent, $needle) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Evaluate a request and, when warranted, record the finding + fire the event.
     * Returns the finding only when it is actionable (i.e. not an accepted
     * false positive), so callers may block on it.
     */
    public function handle(Request $request): ?InspectionResult
    {
        // Count the request towards the client's flood budget before the
        // read-only inspection checks it.
        if (config('waf.ddos.enabled', true)) {
            $this->flood->hit((string) $request->ip());
        }

        $result = $this->inspect($request);

        if (! $result->isThreat() || $result->confidenceScore() < (int) config('waf.min_confidence', 10)) {
            return null;
        }

        // Accepted false positives are still recorded for the audit trail, but
        // withheld from the caller so they never trigger a block.
        $accepted = $this->exclusions->accepts($result->summary(), $request->fullUrl());

        $this->record($request, $result, $accepted);

        return $accepted ? null : $result;
    }

    /**
     * Whether a finding warrants an actual block: only in blocking mode, and
     * then either once the confidence clears `block_confidence` or — when
     * `ddos.block` is on — on the volumetric flood signal alone.
     */
    public function shouldBlock(InspectionResult $result): bool
    {
        if (config('waf.mode', 'detection') !== 'blocking') {
            return false;
        }

        // A flood's confidence score sits below the usual block threshold by
        // design (25), so blocking it is gated on an explicit opt-in rather
        // than on the score.
        if ($result->isDdos && config('waf.ddos.block', false)) {
            return true;
        }

        return $result->confidenceScore() >= (int) config('waf.block_confidence', 60);
    }

    /**
     * Slice the request into the named surfaces the signatures target.
     *
     * @return array<string, string>
     */
    private function collectSurfaces(Request $request): array
    {
        return [
            'query' => $this->querySurface($request),
            'body' => $this->bodySurface($request),
            'path' => $this->normalise(rawurldecode($request->getPathInfo())),
            'headers' => $this->headerSurface($request),
            'cookie' => $this->stringify($request->cookies->all()),
        ];
    }

    /**
     * The query as both its raw `?a=b&c=d` string (so URL-syntax signatures
     * work) and its parsed form (so signatures that read decoded values and
     * nested keys work). A leading "?" is prepended so the very first parameter
     * is anchored the same way as the rest.
     */
    private function querySurface(Request $request): string
    {
        $parts = [];

        $raw = $request->getQueryString();
        if ($raw !== null && $raw !== '') {
            $parts[] = $this->normalise('?'.rawurldecode($raw));
        }

        $params = $request->query->all();
        if ($params !== []) {
            $parts[] = $this->stringify($params);
        }

        return implode("\n", $parts);
    }

    /**
     * The body as its parsed fields (uploaded binaries removed), the client
     * names of any uploaded files, and its raw content — covering form-encoded,
     * JSON, XML and multipart payloads alike.
     */
    private function bodySurface(Request $request): string
    {
        $parts = [];

        $fields = $request->request->all();
        foreach (array_keys($request->allFiles()) as $fileField) {
            unset($fields[$fileField]);
        }
        if ($fields !== []) {
            $parts[] = $this->stringify($fields);
        }

        $names = $this->uploadedFileNames($request);
        if ($names !== []) {
            $parts[] = $this->normalise(implode("\n", $names));
        }

        $raw = (string) $request->getContent();
        if ($raw !== '') {
            $parts[] = $this->normalise($raw);
        }

        return implode("\n", $parts);
    }

    /**
     * Client-supplied names of uploaded files (e.g. a `c99.php` web shell).
     * The binary content itself is never scanned.
     *
     * @return array<int, string>
     */
    private function uploadedFileNames(Request $request): array
    {
        $names = [];

        foreach (Arr::flatten($request->allFiles()) as $file) {
            if ($file instanceof UploadedFile) {
                $names[] = (string) $file->getClientOriginalName();
            }
        }

        return array_values(array_filter($names));
    }

    /**
     * Header values worth inspecting, dropping transport plumbing and the
     * cookie header (cookies are inspected on their own surface).
     */
    private function headerSurface(Request $request): string
    {
        $ignore = ['host', 'cookie', 'content-length', 'accept-encoding', 'accept-language', 'connection'];

        $pairs = [];
        foreach ($request->headers->all() as $name => $values) {
            if (in_array($name, $ignore, true)) {
                continue;
            }
            $pairs[$name] = implode(' ', array_slice((array) $values, 0, 2));
        }

        return $pairs === [] ? '' : $this->stringify($pairs);
    }

    private function stringify(array $data): string
    {
        return $data === [] ? '' : $this->normalise((string) json_encode($data, JSON_UNESCAPED_SLASHES));
    }

    /**
     * Trim to the byte cap, then expose the payload alongside a series of
     * decoded views so evasion via encoding can't hide a signature. Each
     * transform is only appended when it actually changes the string:
     *
     *   1. percent-decoding (twice, to unwrap double URL-encoding)
     *   2. HTML-entity decoding (e.g. `&lt;script&gt;` → `<script>`)
     *   3. null-byte stripping (e.g. `<scr%00ipt>` → `<script>`)
     */
    private function normalise(string $raw): string
    {
        // Oversized payloads are sampled head + tail rather than hard-truncated,
        // so prepending junk can't push an attack past the inspected window.
        if (strlen($raw) > self::SURFACE_LIMIT) {
            $raw = substr($raw, 0, self::SURFACE_LIMIT)."\n".substr($raw, -self::SURFACE_TAIL);
        }

        $variants = [$raw];

        $url = rawurldecode(rawurldecode($raw));
        if ($url !== $raw) {
            $variants[] = $url;
        }

        $html = html_entity_decode($url, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        if ($html !== $url) {
            $variants[] = $html;
        }

        $denulled = str_replace("\0", '', $html);
        if ($denulled !== $html) {
            $variants[] = $denulled;
        }

        return implode("\n", array_unique($variants));
    }

    /**
     * Test every signature against the surfaces it targets, keeping the first
     * hit per signature.
     *
     * @param  array<string, string>  $surfaces
     * @return array<int, SignatureMatch>
     */
    private function scan(array $surfaces): array
    {
        $hits = [];

        $level = (int) config('waf.paranoia_level', 2);
        $mutedRules = (array) config('waf.disabled_rules', []);
        $mutedCategories = (array) config('waf.disabled_categories', []);

        foreach (array_merge(CoreRuleSet::rules(), $this->extraSignatures()) as $signature) {
            if (in_array($signature->id, $mutedRules, true)
                || in_array($signature->category, $mutedCategories, true)
                || ! $signature->firesAtParanoia($level)) {
                continue;
            }

            foreach ($signature->targets as $surface) {
                $subject = $surfaces[$surface] ?? '';

                if ($subject === '') {
                    continue;
                }

                $matched = $signature->match($subject);
                if ($matched !== null) {
                    $hits[] = $signature->hit($surface, $matched);

                    break;
                }
            }
        }

        return $hits;
    }

    /** Compiled operator signatures, memoised per distinct configuration. */
    private static array $compiled = [];

    /**
     * Turn the shipped pack + operator `custom_patterns` into runnable
     * signatures. Bad expressions are reported once and dropped.
     *
     * @return array<int, Signature>
     */
    private function extraSignatures(): array
    {
        $pack = config('waf.pattern_pack', true) ? (array) config('waf-patterns.custom', []) : [];
        $operator = (array) config('waf.custom_patterns', []);
        $fallback = config('waf.custom_pattern_severity', 'error');
        $fallback = in_array($fallback, self::SEVERITIES, true) ? $fallback : 'error';
        $defaultParanoia = (int) config('waf.custom_pattern_paranoia', 1);

        // Operator entries take precedence on a shared regex key.
        $definitions = array_merge($pack, $operator);

        $fingerprint = md5(serialize($definitions).$fallback.$defaultParanoia);

        return self::$compiled[$fingerprint] ??= $this->compile($definitions, $fallback, $defaultParanoia);
    }

    /**
     * @param  array<string, mixed>  $definitions
     * @return array<int, Signature>
     */
    private function compile(array $definitions, string $fallback, int $defaultParanoia): array
    {
        $everySurface = ['query', 'body', 'path', 'headers', 'cookie'];
        $signatures = [];
        $n = 0;

        foreach ($definitions as $regex => $definition) {
            $n++;

            if (@preg_match($regex, '') === false) {
                Log::warning('laravel-waf: dropping unparsable custom pattern', ['pattern' => $regex]);

                continue;
            }

            $rich = is_array($definition);
            $severity = $rich ? ($definition['severity'] ?? $fallback) : $fallback;

            $signatures[] = new Signature(
                id: 'CUSTOM-'.$n,
                category: 'custom',
                name: 'Custom Pattern',
                description: $rich ? ($definition['label'] ?? 'Custom Pattern') : (string) $definition,
                severity: in_array($severity, self::SEVERITIES, true) ? $severity : $fallback,
                targets: $rich ? ($definition['targets'] ?? $everySurface) : $everySurface,
                regex: $regex,
                paranoia: $rich ? (int) ($definition['paranoia'] ?? $defaultParanoia) : $defaultParanoia,
                decisive: $rich && (bool) ($definition['decisive'] ?? false),
                validator: $rich && isset($definition['validator']) ? (string) $definition['validator'] : null,
            );
        }

        return $signatures;
    }

    /**
     * Store the finding (inline or via queue) and broadcast it. A short-lived
     * throttle key collapses bursts of the same finding from one client.
     */
    private function record(Request $request, InspectionResult $result, bool $accepted): void
    {
        $ip = (string) $request->ip();
        $signature = $result->summary();

        // The dedup key optionally folds in the request path, so the same attack
        // aimed at many endpoints is not collapsed into a single finding (which
        // would hide its breadth from the correlation analytics).
        $scope = config('waf.dedup_include_path', false)
            ? $ip.'#'.$request->path().'#'.$signature
            : $ip.'#'.$signature;

        $hash = md5($scope);
        $seenKey = 'laravel-waf|seen|'.$hash;
        $window = now()->addMinutes((int) config('waf.dedup_minutes', 5));

        // Cache::add is atomic: a false return means we saw this very recently.
        // Rather than drop the duplicate outright, bump the hit counter on the
        // finding it collapses into, so the true volume stays visible to the
        // correlation analytics without writing a new row.
        if (! Cache::add($seenKey, true, $window)) {
            $this->bumpHitCount($hash);

            return;
        }

        // A stable id that identifies this finding in both the sync and queued
        // storage paths, so a ThreatDetected listener can reference the row.
        $eventId = (string) Str::uuid();

        // Mask any captured secrets before they touch storage.
        $secrets = $this->redactor->sensitiveValues($result->matches);
        $url = $this->redactor->scrub(mb_substr($request->fullUrl(), 0, 2000), $secrets);
        $payload = $this->redactor->scrub(mb_substr($this->evidence($result), 0, 4000), $secrets);

        $row = [
            'event_id' => $eventId,
            'ip_address' => $ip,
            'method' => $request->method(),
            'url' => $url,
            'user_agent' => mb_substr((string) $request->userAgent(), 0, 500),
            'type' => $signature,
            'category' => $this->classify($result),
            'rule_ids' => implode(',', $result->ruleIds()),
            'payload' => $payload,
            'threat_level' => $result->severity(),
            'anomaly_score' => $result->anomalyScore(),
            'confidence_score' => $result->confidenceScore(),
            'confidence_label' => $result->confidenceLabel(),
            'action_taken' => $this->action($result, $accepted),
            'hit_count' => 1,
            'user_id' => Auth::id(),
            'created_at' => now(),
            'updated_at' => now(),
        ];

        $id = $this->persist($row);

        // Remember the row id (inline path only) so later duplicates within the
        // window can bump its hit counter instead of being dropped silently.
        if ($id !== null) {
            Cache::put($seenKey, $id, $window);
        }

        Log::warning('laravel-waf finding recorded', [
            'ip' => $ip,
            'event_id' => $eventId,
            'signature' => $signature,
            'severity' => $result->severity(),
            'confidence' => $result->confidenceScore(),
            'action' => $row['action_taken'],
        ]);

        ThreatDetected::dispatch($row, $result, $ip, $eventId);
    }

    /**
     * Account for a duplicate that the dedup window collapsed into an existing
     * finding by bumping its hit counter.
     *
     * The row id was cached against the dedup key when the finding was first
     * written. It is only present on the inline storage path — under queueing
     * the row doesn't exist yet, so duplicates there are simply not tallied.
     *
     * To keep this off the database on a route under attack, the bumps are
     * accumulated in the cache and flushed to the row at most once per
     * `dedup_flush_seconds` (so the stored count is eventually consistent, up
     * to a small tail loss if the attack stops mid-interval). Set the interval
     * to 0 to write every bump straight through.
     */
    private function bumpHitCount(string $hash): void
    {
        $id = Cache::get('laravel-waf|seen|'.$hash);

        if (! is_int($id)) {
            return;
        }

        $flushSeconds = (int) config('waf.dedup_flush_seconds', 10);

        if ($flushSeconds <= 0) {
            $this->applyHitCount($id, 1);

            return;
        }

        // Accumulate the bump in the cache — atomic and off the database.
        $pendingKey = 'laravel-waf|pending|'.$hash;
        $window = now()->addMinutes((int) config('waf.dedup_minutes', 5));
        Cache::add($pendingKey, 0, $window);
        Cache::increment($pendingKey);

        // Flush the accumulated count in a single write, at most once per
        // interval. The cooldown slot is claimed atomically with Cache::add.
        $flushKey = 'laravel-waf|flushed|'.$hash;
        if (! Cache::add($flushKey, true, now()->addSeconds($flushSeconds))) {
            return;
        }

        $amount = (int) Cache::get($pendingKey, 0);
        if ($amount > 0) {
            // Decrement (not pull) so bumps landing between the read and here
            // stay counted for the next flush rather than being lost.
            Cache::decrement($pendingKey, $amount);
            $this->applyHitCount($id, $amount);
        }
    }

    private function applyHitCount(int $id, int $amount): void
    {
        try {
            DB::table(config('waf.table_name', 'waf_logs'))
                ->where('id', $id)
                ->increment('hit_count', $amount, ['updated_at' => now()]);
        } catch (\Throwable $e) {
            Log::error('laravel-waf: could not bump hit count', ['error' => $e->getMessage()]);
        }
    }

    /**
     * @param  array<string, mixed>  $row
     * @return int|null the inserted row id (inline path), or null when queued
     */
    private function persist(array $row): ?int
    {
        if (config('waf.queue.enabled', false)) {
            StoreWafLog::dispatch($row)
                ->onConnection(config('waf.queue.connection'))
                ->onQueue(config('waf.queue.queue', 'default'));

            return null;
        }

        try {
            return (int) DB::table(config('waf.table_name', 'waf_logs'))->insertGetId($row);
        } catch (\Throwable $e) {
            Log::error('laravel-waf: could not persist finding', ['error' => $e->getMessage()]);

            return null;
        }
    }

    private function classify(InspectionResult $result): string
    {
        if (! empty($result->matches)) {
            return $result->matches[0]->category;
        }

        return match (true) {
            $result->isScanner => 'scanner',
            $result->isDdos => 'ddos',
            default => 'bot',
        };
    }

    private function action(InspectionResult $result, bool $accepted): string
    {
        if ($accepted) {
            return 'excluded';
        }

        return $this->shouldBlock($result) ? 'blocked' : 'logged';
    }

    private function evidence(InspectionResult $result): string
    {
        $lines = array_map(
            fn (SignatureMatch $hit) => "{$hit->id} @ {$hit->context} => {$hit->matched}",
            $result->matches,
        );

        if ($result->isDdos) {
            $lines[] = 'flood: hit rate over the configured ceiling';
        }

        return implode("\n", $lines);
    }
}
