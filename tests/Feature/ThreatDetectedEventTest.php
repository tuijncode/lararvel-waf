<?php

use Illuminate\Support\Facades\Event;
use Tuijncode\LaravelWaf\Events\ThreatDetected;
use Tuijncode\LaravelWaf\Services\InspectionResult;

it('dispatches ThreatDetected with the log row, result and ip', function () {
    Event::fake([ThreatDetected::class]);

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    Event::assertDispatched(ThreatDetected::class, function (ThreatDetected $event) {
        return $event->result instanceof InspectionResult
            && $event->ipAddress === '127.0.0.1'
            && $event->log['category'] === 'sqli'
            && $event->log['threat_level'] === 'critical'
            && str_contains($event->log['type'], '942100')
            && $event->log['confidence_score'] > 0
            && in_array('942100', $event->result->ruleIds(), true);
    });
});

it('does not dispatch for a clean request', function () {
    Event::fake([ThreatDetected::class]);

    $this->get('/?q=hello', ['User-Agent' => 'Mozilla/5.0 (clean browser)'])->assertOk();

    Event::assertNotDispatched(ThreatDetected::class);
});
