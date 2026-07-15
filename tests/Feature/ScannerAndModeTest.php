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

it('records a bot-only client as a finding', function () {
    $this->get('/?q=hello', ['User-Agent' => 'curl/8.4.0']);

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('bot')
        ->and($log->type)->toContain('cURL');
});

it('exempts a whitelisted user-agent from bot detection', function () {
    config()->set('waf.whitelisted_agents', ['UptimeRobot', 'curl']);

    $this->get('/?q=hello', ['User-Agent' => 'curl/8.4.0']);

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('still flags an attack from a whitelisted agent', function () {
    config()->set('waf.whitelisted_agents', ['curl']);

    // The bot signal is suppressed, but the SQLi signature still fires.
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"), ['User-Agent' => 'curl/8.4.0']);

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('sqli');
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
