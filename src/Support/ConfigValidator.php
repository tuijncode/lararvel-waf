<?php

namespace Tuijncode\LaravelWaf\Support;

use Tuijncode\LaravelWaf\Rules\CoreRuleSet;
use Tuijncode\LaravelWaf\Rules\Signature;

/**
 * Sanity-checks the published configuration so a typo in `.env` (e.g.
 * WAF_MODE=blockign or WAF_PARANOIA=9) surfaces as a clear warning instead of
 * silently changing how the firewall behaves.
 */
class ConfigValidator
{
    private const SEVERITIES = ['critical', 'error', 'warning', 'notice'];

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
        $this->oneOf($problems, 'waf.custom_pattern_severity', self::SEVERITIES);

        $this->intRange($problems, 'waf.paranoia_level', 1, 4);
        $this->intRange($problems, 'waf.custom_pattern_paranoia', 1, 4);
        $this->intRange($problems, 'waf.min_confidence', 0, 100);
        $this->intRange($problems, 'waf.block_confidence', 0, 100);
        $this->intRange($problems, 'waf.block_response.status', 100, 599);
        $this->intRange($problems, 'waf.dedup_minutes', 0, 1440);

        $this->positiveInt($problems, 'waf.ddos.threshold');
        $this->positiveInt($problems, 'waf.ddos.window');

        $this->knownCategories($problems);

        return $problems;
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
