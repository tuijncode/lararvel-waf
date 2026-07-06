<?php

namespace Tuijncode\LaravelWaf\Services;

/**
 * A User-Agent classification produced by the scanner or bot detector: a
 * human-readable name and the severity to attribute to the finding.
 */
final class Detection
{
    public function __construct(
        public readonly string $name,
        public readonly string $severity,
    ) {}
}
