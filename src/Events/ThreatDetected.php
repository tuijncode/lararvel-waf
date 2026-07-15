<?php

namespace Tuijncode\LaravelWaf\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Tuijncode\LaravelWaf\Services\InspectionResult;

/**
 * Fired whenever the WAF logs a threat.
 *
 * Listen for this event to implement your own response — block the request,
 * ban the IP, notify a channel, feed a SIEM, etc.
 *
 * Example:
 *
 *   Event::listen(ThreatDetected::class, function (ThreatDetected $event) {
 *       if ($event->result->confidenceScore() >= 80) {
 *           Firewall::ban($event->ipAddress);
 *       }
 *   });
 */
class ThreatDetected
{
    use Dispatchable, SerializesModels;

    /**
     * @param  array<string, mixed>  $log  the row written to the waf_logs table
     * @param  ?string  $eventId  UUID identifying this finding in the log table,
     *                            available even when the insert is queued
     */
    public function __construct(
        public readonly array $log,
        public readonly InspectionResult $result,
        public readonly ?string $ipAddress = null,
        public readonly ?string $eventId = null,
    ) {}
}
