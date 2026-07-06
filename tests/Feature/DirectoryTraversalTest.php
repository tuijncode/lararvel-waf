<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Tuijncode\LaravelWaf\Events\ThreatDetected;

// http://localhost:8000/?file=../../etc/passwd
it('detects and logs a directory traversal attempt', function () {
    Event::fake([ThreatDetected::class]);

    $response = $this->get('/?file='.rawurlencode('../../etc/passwd'));

    $response->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('lfi')
        ->and($log->rule_ids)->toContain('930110'); // /etc/passwd access

    Event::assertDispatched(ThreatDetected::class, function (ThreatDetected $event) {
        $ids = $event->result->ruleIds();

        return in_array('930100', $ids, true) || in_array('930110', $ids, true);
    });
});
