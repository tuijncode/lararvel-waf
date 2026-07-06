<?php

use Tuijncode\LaravelWaf\Rules\SignatureMatch;
use Tuijncode\LaravelWaf\Services\Redactor;

beforeEach(fn () => $this->redactor = new Redactor);

function sig(string $description, string $category = 'custom', string $matched = 'x'): SignatureMatch
{
    return new SignatureMatch('id', $category, 'name', $description, 'critical', 'query', $matched);
}

it('masks the middle of a value', function () {
    expect($this->redactor->mask('AKIAIOSFODNN7EXAMPLE'))
        ->toStartWith('AK')
        ->toEndWith('LE')
        ->not->toContain('IOSFODNN')
        ->toContain('*');
});

it('fully masks very short values', function () {
    expect($this->redactor->mask('abcd'))->toBe('****')
        ->and($this->redactor->mask('x'))->toBe('*');
});

it('flags secret-bearing findings as sensitive', function () {
    expect($this->redactor->isSensitive(sig('AWS Access Key ID')))->toBeTrue()
        ->and($this->redactor->isSensitive(sig('Password in URL')))->toBeTrue()
        ->and($this->redactor->isSensitive(sig('Credit / Debit Card Number')))->toBeTrue()
        ->and($this->redactor->isSensitive(sig('SQL Injection', 'sqli')))->toBeFalse();
});

it('scrubs sensitive values out of text', function () {
    $scrubbed = $this->redactor->scrub('token=AKIAIOSFODNN7EXAMPLE&x=1', ['AKIAIOSFODNN7EXAMPLE']);

    expect($scrubbed)->not->toContain('AKIAIOSFODNN7EXAMPLE')->toContain('&x=1');
});

it('collects only sensitive matched values', function () {
    $matches = [sig('AWS Access Key ID', 'custom', 'AKIA123'), sig('SQL Injection', 'sqli', "' OR 1=1")];

    expect($this->redactor->sensitiveValues($matches))->toBe(['AKIA123']);
});
