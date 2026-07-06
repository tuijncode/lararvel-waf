<?php

use Illuminate\Support\Facades\DB;

beforeEach(fn () => config()->set('waf.pattern_pack', false)); // isolate user patterns

it('detects a user-defined simple custom pattern', function () {
    config()->set('waf.custom_patterns', [
        '/\bmy-secret-token\b/i' => 'Internal Token Leak',
    ]);

    $this->get('/?q='.rawurlencode('here is my-secret-token'))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('custom')
        ->and($log->type)->toContain('Internal Token Leak')
        ->and($log->rule_ids)->toContain('CUSTOM-1')
        ->and($log->threat_level)->toBe('error'); // default custom severity
});

it('honours the severity and targets of a full custom pattern definition', function () {
    config()->set('waf.custom_patterns', [
        '/forbidden/i' => [
            'label' => 'Forbidden Keyword',
            'severity' => 'critical',
            'targets' => ['query'],
        ],
    ]);

    $this->get('/?q=forbidden')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->threat_level)->toBe('critical')
        ->and($log->type)->toContain('Forbidden Keyword');
});

it('skips an invalid custom pattern without breaking inspection', function () {
    config()->set('waf.custom_patterns', [
        '/broken(/' => 'Never Compiles',            // invalid regex
        '/\bhit\b/i' => 'Valid One',
    ]);

    $this->get('/?q=hit')->assertOk();

    expect(DB::table('waf_logs')->where('type', 'like', '%Valid One%')->count())->toBe(1);
});
