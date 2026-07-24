<?php

use Illuminate\Support\Facades\DB;

it('detects the newly added attack classes in the query string', function (string $query, string $ruleId, string $category) {
    $this->get('/?'.$query)->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain($ruleId)
        ->and($log->category)->toBe($category);
})->with([
    // `touch /tmp/pwn` avoids the unix-binary and command-chaining rules, so
    // this row proves the Shellshock signature itself fires.
    'Shellshock' => ['ua='.rawurlencode('() { :;}; touch /tmp/pwn'), '932140', 'rce'],
    'Windows cmd.exe' => ['c='.rawurlencode('cmd.exe /c whoami'), '932150', 'rce'],
    'Windows PowerShell' => ['c='.rawurlencode('powershell -enc SQBFAFgA'), '932150', 'rce'],
    'Encoded loopback SSRF (hex)' => ['url='.rawurlencode('http://0x7f000001/latest'), '934130', 'ssrf'],
    'Encoded loopback SSRF (decimal)' => ['url='.rawurlencode('http://2130706433/'), '934130', 'ssrf'],
    'DNS rebinding domain' => ['url='.rawurlencode('http://127.0.0.1.nip.io/'), '934140', 'ssrf'],
    'SQL CHAR() encoding' => ['q='.rawurlencode('CHAR(83,69,76,69,67,84)'), '942180', 'sqli'],
    // A benign replacement keeps the payload clear of the system()/RCE rules,
    // isolating the /e-modifier signature.
    'PHP preg_replace /e' => ['x='.rawurlencode("preg_replace('/.*/e','1','x')"), '933140', 'php'],
    'PHP allow_url_include' => ['x=allow_url_include', '933140', 'php'],
    'LDAP injection' => ['filter='.rawurlencode('*)(uid=*)'), '943100', 'ldapi'],
    'XPath injection' => ['q='.rawurlencode("//user[name='x']"), '943110', 'xpathi'],
    'CSS expression XSS' => ['x='.rawurlencode('style=color:expression(1)'), '941170', 'xss'],
    'SQL UNHEX encoding' => ['q='.rawurlencode('UNHEX(4142)'), '942190', 'sqli'],
    'PHP get_current_user' => ['x='.rawurlencode('get_current_user()'), '933140', 'php'],
]);

it('detects a Drupalgeddon render-array injection', function () {
    // %23 keeps the '#' in the query value instead of it starting a URL fragment.
    $this->get('/?e=%23post_render')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('custom')
        ->and($log->type)->toContain('Drupalgeddon');
});

it('does not flag a lone CHAR() with too few arguments', function () {
    // CHAR(10) is a legitimate newline; only a multi-code run is the bypass.
    $this->get('/?q='.rawurlencode('CHAR(10)'))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('does not flag prose that merely mentions powershell', function () {
    // The Windows rule requires an executable plus a flag/verb, not the bare word.
    $this->get('/?note='.rawurlencode('powershell is a great tool for admins'))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('keeps the FP-prone LDAP and XPath rules off at paranoia level 1', function (string $query) {
    config()->set('waf.paranoia_level', 1);

    $this->get('/?'.$query)->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
})->with([
    'LDAP' => ['filter='.rawurlencode('*)(uid=*)')],
    'XPath' => ['q='.rawurlencode("//user[name='x']")],
]);
