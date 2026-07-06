<?php

use Illuminate\Support\Facades\DB;

it('detects a known security scanner by its user-agent', function () {
    $this->get('/', ['User-Agent' => 'sqlmap/1.7.2#stable (https://sqlmap.org)']);

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('scanner')
        ->and($log->threat_level)->toBe('critical')
        ->and($log->type)->toContain('SQLMap');
});

it('lets a clean request through without logging', function () {
    $response = $this->get('/?q=hello+world', [
        'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    ]);

    $response->assertOk()->assertSee('ok');

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('blocks high-confidence requests with a 403 in blocking mode', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 60);

    $response = $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"), [
        'User-Agent' => 'sqlmap/1.7.2#stable',
    ]);

    $response->assertForbidden();

    expect(DB::table('waf_logs')->where('action_taken', 'blocked')->count())->toBe(1);
});
