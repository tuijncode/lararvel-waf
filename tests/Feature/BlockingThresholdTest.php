<?php

use Illuminate\Support\Facades\DB;

beforeEach(fn () => config()->set('waf.mode', 'blocking'));

it('blocks a high-confidence request', function () {
    config()->set('waf.block_confidence', 40);

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"), [
        'User-Agent' => 'sqlmap/1.7',
    ])->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('logs but lets through a finding below the block threshold', function () {
    config()->set('waf.block_confidence', 90);

    // An open-redirect probe scores in the medium band — logged, not blocked.
    $this->get('/?next=//evil.example')->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('never blocks in detection mode', function () {
    config()->set('waf.mode', 'detection');
    config()->set('waf.block_confidence', 0);

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"), [
        'User-Agent' => 'sqlmap/1.7',
    ])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});
