<?php

namespace Tuijncode\LaravelWaf\Services;

use Illuminate\Support\Facades\RateLimiter;

/**
 * Volumetric abuse detector.
 *
 * Leans on the framework's own rate limiter to count hits per client inside a
 * decaying window, keeping this class free of any store-specific bookkeeping.
 */
class DdosMonitor
{
    public function __construct(
        protected int $ceiling = 300,
        protected int $windowSeconds = 60,
    ) {
        $this->ceiling = (int) config('waf.ddos.threshold', $ceiling);
        $this->windowSeconds = (int) config('waf.ddos.window', $windowSeconds);
    }

    /**
     * Register a hit for the client and report whether it has gone over budget.
     */
    public function tripped(string $client): bool
    {
        $bucket = 'laravel-waf|flood|'.sha1($client);

        $hits = RateLimiter::hit($bucket, $this->windowSeconds);

        return $hits > $this->ceiling;
    }

    public function ceiling(): int
    {
        return $this->ceiling;
    }

    public function windowSeconds(): int
    {
        return $this->windowSeconds;
    }
}
