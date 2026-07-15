<?php

namespace Tuijncode\LaravelWaf\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * Fired when the auto-ban manager bans an IP after repeated blocks.
 *
 * Listen for this to mirror the ban into a longer-lived store, a firewall, or
 * an alert. The cache-based ban already stands regardless of what listeners do.
 */
class IpBanned
{
    use Dispatchable;

    public function __construct(
        public readonly string $ipAddress,
        public readonly int $seconds,
    ) {}
}
