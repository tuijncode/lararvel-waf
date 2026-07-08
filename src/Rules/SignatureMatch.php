<?php

namespace Tuijncode\LaravelWaf\Rules;

/**
 * A signature that fired: which rule matched, on which request surface, and
 * the exact substring that triggered it.
 */
final class SignatureMatch
{
    public function __construct(
        public readonly string $id,
        public readonly string $category,
        public readonly string $name,
        public readonly string $description,
        public readonly string $severity,
        public readonly string $context,
        public readonly string $matched,
        public readonly bool $decisive = false,
    ) {}

    public function anomalyScore(): int
    {
        return CoreRuleSet::SEVERITY_SCORES[$this->severity] ?? 2;
    }
}
