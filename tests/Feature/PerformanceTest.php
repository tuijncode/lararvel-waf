<?php

use Illuminate\Http\Request;
use Tuijncode\LaravelWaf\Facades\Waf;

$browser = ['HTTP_USER_AGENT' => 'Mozilla/5.0'];

// Payloads crafted to stress greedy/backtracking regexes. With the per-surface
// byte cap in place, none of these should take meaningful time to inspect.
it('inspects pathological payloads well within a time budget', function (string $payload) use ($browser) {
    $request = Request::create('/?q='.rawurlencode($payload), 'GET', [], [], [], $browser);

    $start = microtime(true);
    Waf::inspect($request);
    $elapsed = microtime(true) - $start;

    expect($elapsed)->toBeLessThan(0.5);
})->with([
    'long a-run' => [str_repeat('a', 200000)],
    'nested traversal' => [str_repeat('../', 50000)],
    'brace flood' => [str_repeat('{{', 40000)],
    'angle flood' => [str_repeat('<', 40000)],
    'quote flood' => [str_repeat("'", 40000)],
    'base64 flood' => [str_repeat('ABCd1234', 20000)],
    'union flood' => [str_repeat('union select ', 5000)],
]);

it('still detects an attack buried in a large payload', function () use ($browser) {
    $payload = str_repeat('a', 5000)."' UNION SELECT * FROM users--";
    $request = Request::create('/?q='.rawurlencode($payload), 'GET', [], [], [], $browser);

    expect(Waf::inspect($request)->ruleIds())->toContain('942100');
});
