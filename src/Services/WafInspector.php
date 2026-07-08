<?php

namespace Tuijncode\LaravelWaf\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
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
     * Evaluate a request. This is read-only: nothing is stored or dispatched.
     */
    public function inspect(Request $request): InspectionResult
    {
        $surfaces = $this->collectSurfaces($request);
        $hits = $this->scan($surfaces);

        $agent = (string) ($request->userAgent() ?? '');
        $scanner = $this->scanners->detect($agent);
        $bot = $scanner ? null : $this->bots->detect($agent);
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
     * Evaluate a request and, when warranted, record the finding + fire the event.
     * Returns the finding only when it is actionable (i.e. not an accepted
     * false positive), so callers may block on it.
     */
    public function handle(Request $request): ?InspectionResult
    {
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
     * Whether a finding warrants an actual block: only in blocking mode and
     * only once the confidence clears `block_confidence`.
     */
    public function shouldBlock(InspectionResult $result): bool
    {
        return config('waf.mode', 'detection') === 'blocking'
            && $result->confidenceScore() >= (int) config('waf.block_confidence', 60);
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
     * The body as both its parsed fields (uploaded binaries removed) and its
     * raw content, covering form-encoded, JSON and XML payloads alike.
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

        $raw = (string) $request->getContent();
        if ($raw !== '') {
            $parts[] = $this->normalise($raw);
        }

        return implode("\n", $parts);
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
        $raw = substr($raw, 0, self::SURFACE_LIMIT);

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

        $throttle = 'laravel-waf|seen|'.md5($ip.'#'.$signature);
        $window = now()->addMinutes((int) config('waf.dedup_minutes', 5));

        // Cache::add is atomic: a false return means we saw this very recently.
        if (! Cache::add($throttle, 1, $window)) {
            return;
        }

        // Mask any captured secrets before they touch storage.
        $secrets = $this->redactor->sensitiveValues($result->matches);
        $url = $this->redactor->scrub(mb_substr($request->fullUrl(), 0, 2000), $secrets);
        $payload = $this->redactor->scrub(mb_substr($this->evidence($result), 0, 4000), $secrets);

        $row = [
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
            'user_id' => Auth::id(),
            'created_at' => now(),
            'updated_at' => now(),
        ];

        $this->persist($row);

        Log::warning('laravel-waf finding recorded', [
            'ip' => $ip,
            'signature' => $signature,
            'severity' => $result->severity(),
            'confidence' => $result->confidenceScore(),
            'action' => $row['action_taken'],
        ]);

        ThreatDetected::dispatch($row, $result, $ip);
    }

    /**
     * @param  array<string, mixed>  $row
     */
    private function persist(array $row): void
    {
        if (config('waf.queue.enabled', false)) {
            StoreWafLog::dispatch($row)
                ->onConnection(config('waf.queue.connection'))
                ->onQueue(config('waf.queue.queue', 'default'));

            return;
        }

        try {
            DB::table(config('waf.table_name', 'waf_logs'))->insert($row);
        } catch (\Throwable $e) {
            Log::error('laravel-waf: could not persist finding', ['error' => $e->getMessage()]);
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
