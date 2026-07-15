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
     * @param  ?string  $validator  named post-match check the capture must also pass (e.g. 'luhn')
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
        public readonly ?string $validator = null,
    ) {}

    /**
     * The capture must be long enough to cover real secrets in full (JWTs can
     * run to hundreds of characters) — the Redactor masks by replacing the
     * captured value, so a truncated capture would leave the tail unmasked.
     */
    private const CAPTURE_LIMIT = 1024;

    /**
     * Run the signature against a surface, returning the matched substring
     * (capped) on a hit, or null. Malformed regexes are treated as no match.
     *
     * When the signature carries a named validator, each regex candidate must
     * also clear it — so a 16-digit run that fails the Luhn check is not
     * reported as a card number.
     */
    public function match(string $subject): ?string
    {
        if ($this->validator === null) {
            if (@preg_match($this->regex, $subject, $found) !== 1) {
                return null;
            }

            return mb_substr($found[0] ?? '', 0, self::CAPTURE_LIMIT);
        }

        if (@preg_match_all($this->regex, $subject, $found) < 1) {
            return null;
        }

        foreach ($found[0] as $candidate) {
            if (Validators::passes($this->validator, $candidate)) {
                return mb_substr($candidate, 0, self::CAPTURE_LIMIT);
            }
        }

        return null;
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

    public function withValidator(?string $validator): self
    {
        return new self(
            id: $this->id,
            category: $this->category,
            name: $this->name,
            description: $this->description,
            severity: $this->severity,
            targets: $this->targets,
            regex: $this->regex,
            paranoia: $this->paranoia,
            decisive: $this->decisive,
            validator: $validator,
        );
    }
}
