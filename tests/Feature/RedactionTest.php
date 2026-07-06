<?php

use Illuminate\Support\Facades\DB;

it('masks a detected secret in the stored url and payload', function () {
    $this->get('/?token=AKIAIOSFODNN7EXAMPLE')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->type)->toContain('AWS Access Key ID')
        ->and($log->url)->not->toContain('AKIAIOSFODNN7EXAMPLE')
        ->and($log->payload)->not->toContain('AKIAIOSFODNN7EXAMPLE');
});

it('stores the raw value when redaction is disabled', function () {
    config()->set('waf.redact.enabled', false);

    $this->get('/?token=AKIAIOSFODNN7EXAMPLE')->assertOk();

    expect(DB::table('waf_logs')->value('url'))->toContain('AKIAIOSFODNN7EXAMPLE');
});

it('leaves non-sensitive findings untouched', function () {
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    // A SQLi payload is not a secret, so the evidence is stored as-is.
    expect(DB::table('waf_logs')->value('payload'))->toContain('UNION');
});
