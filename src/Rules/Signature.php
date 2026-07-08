<?php

namespace Tuijncode\LaravelWaf\Rules;

/**
 * A single detection signature: one regex, plus the metadata that describes
 * what it catches, how severe a hit is, which request surfaces it inspects and
 * the paranoia level at which it becomes active.
 */
final class Signature
{
    /**
     * @param  array<int, string>  $targets  surfaces to inspect (query, body, path, headers, cookie)
     * @param  bool  $decisive  a hit is a certain attack — forces full confidence and a block
     */
    public function __construct(
        public readonly string $id,
        public readonly string $category,
        public readonly string $name,
        public readonly string $description,
        public readonly string $severity,
        public readonly array $targets,
        public readonly string $regex,
        public readonly int $paranoia = 1,
        public readonly bool $decisive = false,
    ) {}

    /**
     * Run the signature against a surface, returning the matched substring
     * (capped) on a hit, or null. Malformed regexes are treated as no match.
     */
    public function match(string $subject): ?string
    {
        if (@preg_match($this->regex, $subject, $found) !== 1) {
            return null;
        }

        return mb_substr($found[0] ?? '', 0, 200);
    }

    public function firesAtParanoia(int $level): bool
    {
        return $this->paranoia <= $level;
    }

    /**
     * Turn this signature into a concrete match found on a given surface.
     */
    public function hit(string $context, string $matched): SignatureMatch
    {
        return new SignatureMatch(
            id: $this->id,
            category: $this->category,
            name: $this->name,
            description: $this->description,
            severity: $this->severity,
            context: $context,
            matched: $matched,
            decisive: $this->decisive,
        );
    }
}
