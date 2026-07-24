<?php

use Illuminate\Http\Request;
use Tuijncode\LaravelWaf\Facades\Waf;

$browser = ['HTTP_USER_AGENT' => 'Mozilla/5.0'];

// Payloads crafted to stress greedy/backtracking regexes. This is a guard
// against catastrophic backtracking (ReDoS), which shows up as seconds-to-
// minutes of CPU, not micro-benchmarking — with the byte cap and bounded
// spans in place the real cost is tens of milliseconds. The 2s ceiling leaves
// generous room for CI jitter while still failing hard on a runaway regex.
it('inspects pathological payloads well within a time budget', function (string $payload) use ($browser) {
    $request = Request::create('/?q='.rawurlencode($payload), 'GET', [], [], [], $browser);

    $start = microtime(true);
    Waf::inspect($request);
    $elapsed = microtime(true) - $start;

    expect($elapsed)->toBeLessThan(2.0);
})->with([
    'long a-run' => [str_repeat('a', 200000)],
    'nested traversal' => [str_repeat('../', 50000)],
    'brace flood' => [str_repeat('{{', 40000)],
    'ruby interp flood' => [str_repeat('#{', 40000)],
    'dollar-brace flood' => [str_repeat('${', 40000)],
    'jsp flood' => [str_repeat('<%', 40000)],
    'twig-tag flood' => [str_repeat('{%', 40000)],
    'crlf flood' => [str_repeat("\r\n", 40000)],
    'angle flood' => [str_repeat('<', 40000)],
    'quote flood' => [str_repeat("'", 40000)],
    'base64 flood' => [str_repeat('ABCd1234', 20000)],
    'union flood' => [str_repeat('union select ', 5000)],
    // Comment-open floods stress the SQL-comment stripping pass: an unclosed
    // /* must not send the lazy scan quadratic.
    'block-comment-open flood' => [str_repeat('/*', 40000)],
    'exec-comment-open flood' => [str_repeat('/*!', 30000)],
    'line-comment flood' => [str_repeat('-- ', 40000)],
    'hash-comment flood' => [str_repeat('#', 40000)],
    // Backslash-escape decoding must stay linear on a flood of escape openers.
    'backslash-u flood' => [str_repeat('\\u', 40000)],
    'backslash-x flood' => [str_repeat('\\x', 40000)],
]);

it('still detects an attack buried in a large payload', function () use ($browser) {
    $payload = str_repeat('a', 5000)."' UNION SELECT * FROM users--";
    $request = Request::create('/?q='.rawurlencode($payload), 'GET', [], [], [], $browser);

    expect(Waf::inspect($request)->ruleIds())->toContain('942100');
});
