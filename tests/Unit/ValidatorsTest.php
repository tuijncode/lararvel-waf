<?php

use Tuijncode\LaravelWaf\Rules\Validators;

it('passes a Luhn-valid card number', function (string $pan) {
    expect(Validators::passes('luhn', $pan))->toBeTrue();
})->with([
    '4111111111111111', // Visa
    '5500005555555559', // Mastercard
    '340000000000009',  // Amex
    '6011000000000004', // Discover
    '4111-1111-1111-1111', // separators ignored
]);

it('fails a number with the right shape but wrong checksum', function () {
    expect(Validators::passes('luhn', '4111111111111112'))->toBeFalse();
});

it('fails a value with too few digits', function () {
    expect(Validators::passes('luhn', '4111'))->toBeFalse();
});

it('does not suppress on an unknown validator name', function () {
    // Fail open: a typo must not silently disable a signature.
    expect(Validators::passes('nope', 'anything'))->toBeTrue();
});

it('knows its built-in validators', function () {
    expect(Validators::known('luhn'))->toBeTrue()
        ->and(Validators::known('nope'))->toBeFalse();
});
