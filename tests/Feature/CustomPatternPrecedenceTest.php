<?php

use Illuminate\Support\Facades\DB;

it('lets an operator pattern override a pack pattern on the same regex', function () {
    // Same regex key as the bundled npm-token signature.
    config()->set('waf.custom_patterns', [
        '/\bnpm_[0-9A-Za-z]{36}\b/' => 'Overridden npm Rule',
    ]);

    $this->get('/?tok=npm_'.str_repeat('a', 36))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->type)->toContain('Overridden npm Rule')
        ->and($log->type)->not->toContain('npm Access Token');
});

it('runs operator patterns alongside the pack', function () {
    config()->set('waf.custom_patterns', [
        '/\btripwire-42\b/i' => 'Operator Tripwire',
    ]);

    $this->get('/?x=tripwire-42')->assertOk();

    expect(DB::table('waf_logs')->where('type', 'like', '%Operator Tripwire%')->count())->toBe(1);
});
