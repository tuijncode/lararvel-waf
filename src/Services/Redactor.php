<?php

namespace Tuijncode\LaravelWaf\Services;

use Tuijncode\LaravelWaf\Rules\SignatureMatch;

/**
 * Keeps captured secrets out of the log table.
 *
 * The WAF detects API keys, passwords, tokens and card numbers — so the value
 * that tripped the rule must never be stored verbatim, or the `waf_logs` table
 * becomes a honeypot of the very data it protects. This masks those values in
 * anything about to be persisted.
 */
class Redactor
{
    /**
     * Description/category fragments that mark a finding as carrying a secret.
     */
    private const DEFAULT_LABELS = [
        'key', 'token', 'secret', 'password', 'credential',
        'card', 'private key', 'session id', 'jwt', 'oauth', 'bearer',
    ];

    public function enabled(): bool
    {
        return (bool) config('waf.redact.enabled', true);
    }

    /**
     * Does this finding's captured value need masking?
     */
    public function isSensitive(SignatureMatch $match): bool
    {
        $haystack = strtolower($match->description.' '.$match->category);

        foreach ((array) config('waf.redact.labels', self::DEFAULT_LABELS) as $label) {
            if ($label !== '' && str_contains($haystack, strtolower((string) $label))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Mask the middle of a value, keeping just enough at the edges to remain
     * recognisable (e.g. `AKIA…EXAMPLE` → `AK****************LE`).
     */
    public function mask(string $value): string
    {
        $length = mb_strlen($value);

        if ($length <= 4) {
            return str_repeat('*', max($length, 1));
        }

        $keep = $length <= 8 ? 1 : 2;

        return mb_substr($value, 0, $keep)
            .str_repeat('*', $length - (2 * $keep))
            .mb_substr($value, -$keep);
    }

    /**
     * Replace every occurrence of the given sensitive values in a string with
     * their masked form.
     *
     * @param  array<int, string>  $values
     */
    public function scrub(string $text, array $values): string
    {
        foreach ($values as $value) {
            if ($value !== '') {
                $text = str_replace($value, $this->mask($value), $text);
            }
        }

        return $text;
    }

    /**
     * Collect the captured values that must be masked from a set of matches.
     *
     * @param  array<int, SignatureMatch>  $matches
     * @return array<int, string>
     */
    public function sensitiveValues(array $matches): array
    {
        if (! $this->enabled()) {
            return [];
        }

        $values = [];
        foreach ($matches as $match) {
            if ($this->isSensitive($match)) {
                $values[] = $match->matched;
            }
        }

        return array_values(array_unique(array_filter($values)));
    }
}
