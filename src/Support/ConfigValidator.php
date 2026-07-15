<?php

namespace Tuijncode\LaravelWaf\Support;

use Tuijncode\LaravelWaf\Rules\CoreRuleSet;
use Tuijncode\LaravelWaf\Rules\Signature;
use Tuijncode\LaravelWaf\Rules\Validators;

/**
 * Sanity-checks the published configuration so a typo in `.env` (e.g.
 * WAF_MODE=blockign or WAF_PARANOIA=9) surfaces as a clear warning instead of
 * silently changing how the firewall behaves.
 */
class ConfigValidator
{
    private const SEVERITIES = ['critical', 'error', 'warning', 'notice'];

    private const SURFACES = ['query', 'body', 'path', 'headers', 'cookie'];

    /**
     * Return a list of human-readable problems, or an empty array if the
     * configuration is sound.
     *
     * @return array<int, string>
     */
    public function validate(): array
    {
        $problems = [];

        $this->oneOf($problems, 'waf.mode', ['detection', 'blocking']);
        $this->oneOf($problems, 'waf.on_error', ['open', 'closed']);
        $this->oneOf($problems, 'waf.custom_pattern_severity', self::SEVERITIES);

        $this->intRange($problems, 'waf.paranoia_level', 1, 4);
        $this->intRange($problems, 'waf.custom_pattern_paranoia', 1, 4);
        $this->intRange($problems, 'waf.min_confidence', 0, 100);
        $this->intRange($problems, 'waf.block_confidence', 0, 100);
        $this->intRange($problems, 'waf.block_response.status', 100, 599);
        $this->intRange($problems, 'waf.dedup_minutes', 0, 1440);
        $this->intRange($problems, 'waf.dedup_flush_seconds', 0, 3600);

        $this->positiveInt($problems, 'waf.ddos.threshold');
        $this->positiveInt($problems, 'waf.ddos.window');

        $this->positiveInt($problems, 'waf.auto_ban.max_blocks');
        $this->positiveInt($problems, 'waf.auto_ban.window');
        $this->positiveInt($problems, 'waf.auto_ban.duration');

        $this->environments($problems);
        $this->knownCategories($problems);
        $this->customPatterns($problems);

        return $problems;
    }

    /**
     * @param  array<int, string>  $problems
     */
    private function environments(array &$problems): void
    {
        $environments = config('waf.enabled_environments');

        if ($environments !== null && ! is_array($environments)) {
            $problems[] = 'waf.enabled_environments must be null or an array of environment names, got '
                .$this->show($environments).'.';
        }
    }

    /**
     * Check the operator's own signatures (and the published pattern pack): the
     * regex must compile, and any explicit severity or target must be known —
     * a typo in `targets` would otherwise make the pattern silently dead.
     *
     * @param  array<int, string>  $problems
     */
    private function customPatterns(array &$problems): void
    {
        $pack = config('waf.pattern_pack', true) ? (array) config('waf-patterns.custom', []) : [];
        $definitions = array_merge($pack, (array) config('waf.custom_patterns', []));

        foreach ($definitions as $regex => $definition) {
            $regex = (string) $regex;

            if (@preg_match($regex, '') === false) {
                $problems[] = "custom pattern '{$regex}' is not a valid regular expression.";
            }

            if (! is_array($definition)) {
                continue;
            }

            $severity = $definition['severity'] ?? null;
            if ($severity !== null && ! in_array($severity, self::SEVERITIES, true)) {
                $problems[] = "custom pattern '{$regex}' has unknown severity '{$severity}'"
                    .' (allowed: '.implode(', ', self::SEVERITIES).').';
            }

            foreach ((array) ($definition['targets'] ?? []) as $target) {
                if (! in_array($target, self::SURFACES, true)) {
                    $problems[] = "custom pattern '{$regex}' targets unknown surface '{$target}'"
                        .' (known: '.implode(', ', self::SURFACES).').';
                }
            }

            $validator = $definition['validator'] ?? null;
            if ($validator !== null && ! Validators::known((string) $validator)) {
                $problems[] = "custom pattern '{$regex}' names unknown validator '{$validator}'.";
            }
        }
    }

    /**
     * @param  array<int, string>  $problems
     * @param  array<int, string>  $allowed
     */
    private function oneOf(array &$problems, string $key, array $allowed): void
    {
        $value = config($key);

        if (! in_array($value, $allowed, true)) {
            $problems[] = "{$key} must be one of [".implode(', ', $allowed).'], got '.$this->show($value).'.';
        }
    }

    /**
     * @param  array<int, string>  $problems
     */
    private function intRange(array &$problems, string $key, int $min, int $max): void
    {
        $int = filter_var(config($key), FILTER_VALIDATE_INT);

        if ($int === false || $int < $min || $int > $max) {
            $problems[] = "{$key} must be an integer between {$min} and {$max}, got ".$this->show(config($key)).'.';
        }
    }

    /**
     * @param  array<int, string>  $problems
     */
    private function positiveInt(array &$problems, string $key): void
    {
        $int = filter_var(config($key), FILTER_VALIDATE_INT);

        if ($int === false || $int < 1) {
            $problems[] = "{$key} must be a positive integer, got ".$this->show(config($key)).'.';
        }
    }

    /**
     * @param  array<int, string>  $problems
     */
    private function knownCategories(array &$problems): void
    {
        $known = $this->categories();

        foreach ((array) config('waf.disabled_categories', []) as $category) {
            if (! in_array($category, $known, true)) {
                $problems[] = "waf.disabled_categories contains unknown category '{$category}' (known: ".implode(', ', $known).').';
            }
        }
    }

    /**
     * @return array<int, string>
     */
    private function categories(): array
    {
        $core = array_map(fn (Signature $s): string => $s->category, CoreRuleSet::rules());

        return array_values(array_unique(array_merge($core, ['custom', 'scanner', 'bot', 'ddos'])));
    }

    private function show(mixed $value): string
    {
        return is_scalar($value) ? var_export($value, true) : gettype($value);
    }
}
