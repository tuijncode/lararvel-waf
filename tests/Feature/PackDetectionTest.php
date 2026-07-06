<?php

use Illuminate\Support\Facades\DB;

it('detects bundled pack signatures end to end', function (string $query, string $label) {
    $this->get('/?'.$query)->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('custom')
        ->and($log->type)->toContain($label);
})->with([
    'AWS access key' => ['token=AKIAIOSFODNN7EXAMPLE', 'AWS Access Key ID'],
    'GitHub token' => ['t=ghp_'.str_repeat('a', 36), 'GitHub Token'],
    'Ignition RCE probe' => ['x=/_ignition/execute-solution', 'Ignition RCE'],
    'SSTI arithmetic' => ['tpl='.rawurlencode('{{7*7}}'), 'SSTI Arithmetic Probe'],
    'Open redirect' => ['next=//evil.example', 'Open Redirect'],
    'Prototype pollution' => ['__proto__[admin]=1', 'Prototype Pollution'],
    'GraphQL introspection' => ['q='.rawurlencode('{__schema{types{name}}}'), 'GraphQL Introspection'],
]);

it('detects a credit card number in a POST body', function () {
    $this->post('/', ['pan' => '4111111111111111'])->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->type)->toContain('Card Number');
});
