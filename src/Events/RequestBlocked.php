<?php

namespace Tuijncode\LaravelWaf\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Tuijncode\LaravelWaf\Services\InspectionResult;

/**
 * Fired the moment the WAF decides to refuse a request (blocking mode only),
 * just before the block response is returned.
 *
 * Listen for this to ban the IP, increment a metric, or page on-call. The
 * request is still blocked regardless of what listeners do.
 */
class RequestBlocked
{
    use Dispatchable;

    public function __construct(
        public readonly Request $request,
        public readonly InspectionResult $result,
    ) {}
}
