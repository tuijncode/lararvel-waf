<?php

use Illuminate\Support\Facades\DB;

it('reports the signatures a payload trips', function () {
    $this->artisan('waf:test', ['payload' => "' UNION SELECT * FROM users--"])
        ->expectsOutputToContain('942100')
        ->expectsOutputToContain('Confidence')
        ->assertExitCode(0);
});

it('reports a clean payload as no threat', function () {
    $this->artisan('waf:test', ['payload' => 'hello world'])
        ->expectsOutputToContain('No threats detected')
        ->assertExitCode(0);
});

it('surfaces a scanner user-agent', function () {
    $this->artisan('waf:test', ['payload' => 'hello', '--ua' => 'sqlmap/1.7'])
        ->expectsOutputToContain('scanner')
        ->assertExitCode(0);
});

it('rejects a malformed header option', function () {
    $this->artisan('waf:test', ['payload' => 'x', '--header' => ['no-colon-here']])
        ->assertExitCode(2);
});

it('writes nothing to the database (dry run)', function () {
    $this->artisan('waf:test', ['payload' => "' UNION SELECT * FROM users--"])
        ->assertExitCode(0);

    expect(DB::table('waf_logs')->count())->toBe(0);
});
