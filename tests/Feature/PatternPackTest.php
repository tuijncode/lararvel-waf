<?php

use Illuminate\Support\Facades\DB;

it('detects a threat from the bundled pattern pack', function () {
    // Enabled by default; a bundled signature (web shell) should fire.
    $this->get('/?f='.rawurlencode('/uploads/c99.php'))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('custom')
        ->and($log->type)->toContain('Web Shell Signature');
});

it('can be disabled, leaving only core rules and user patterns', function () {
    config()->set('waf.pattern_pack', false);

    // A pack-only signature no longer matches.
    $this->get('/?f='.rawurlencode('/uploads/c99.php'))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});
