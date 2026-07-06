<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Tuijncode\LaravelWaf\Events\ThreatDetected;

// http://localhost:8000/?cmd=system('ls -la')
it('detects and logs a remote code execution attempt', function () {
    Event::fake([ThreatDetected::class]);

    $response = $this->get('/?cmd='.rawurlencode("system('ls -la')"));

    $response->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('rce')
        ->and($log->threat_level)->toBe('critical')
        ->and($log->rule_ids)->toContain('932110'); // system() call

    Event::assertDispatched(ThreatDetected::class, function (ThreatDetected $event) {
        return in_array('932110', $event->result->ruleIds(), true);
    });
});
