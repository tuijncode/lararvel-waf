<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Facades\Waf;
use Tuijncode\LaravelWaf\Services\InspectionResult;

$browser = ['HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'];

it('inspects a request through the facade without side effects', function () use ($browser) {
    $request = Request::create('/?q='.rawurlencode("' UNION SELECT * FROM users--"), 'GET', [], [], [], $browser);

    $result = Waf::inspect($request);

    expect($result)->toBeInstanceOf(InspectionResult::class)
        ->and($result->isThreat())->toBeTrue()
        ->and($result->ruleIds())->toContain('942100')
        ->and($result->confidenceScore())->toBeGreaterThan(0);

    // inspect() is pure — nothing was written.
    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('returns a clean result for a harmless request', function () use ($browser) {
    $result = Waf::inspect(Request::create('/?q=hello', 'GET', [], [], [], $browser));

    expect($result->isThreat())->toBeFalse()
        ->and($result->confidenceScore())->toBe(0);
});
