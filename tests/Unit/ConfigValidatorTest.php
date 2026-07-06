<?php

use Tuijncode\LaravelWaf\Support\ConfigValidator;

beforeEach(fn () => $this->validator = new ConfigValidator);

it('passes the shipped default configuration', function () {
    expect($this->validator->validate())->toBe([]);
});

it('flags an invalid mode', function () {
    config()->set('waf.mode', 'blockign');

    expect($this->validator->validate())->toContain(
        "waf.mode must be one of [detection, blocking], got 'blockign'."
    );
});

it('flags an out-of-range paranoia level', function () {
    config()->set('waf.paranoia_level', 9);

    expect(implode(' ', $this->validator->validate()))->toContain('waf.paranoia_level');
});

it('flags a severity typo', function () {
    config()->set('waf.custom_pattern_severity', 'criticl');

    expect(implode(' ', $this->validator->validate()))->toContain('waf.custom_pattern_severity');
});

it('flags a confidence value outside 0-100', function () {
    config()->set('waf.block_confidence', 150);

    expect(implode(' ', $this->validator->validate()))->toContain('waf.block_confidence');
});

it('flags a non-positive ddos threshold', function () {
    config()->set('waf.ddos.threshold', 0);

    expect(implode(' ', $this->validator->validate()))->toContain('waf.ddos.threshold');
});

it('flags an unknown disabled category', function () {
    config()->set('waf.disabled_categories', ['sqli', 'notacategory']);

    expect(implode(' ', $this->validator->validate()))->toContain("unknown category 'notacategory'");
});

it('accepts a valid known disabled category', function () {
    config()->set('waf.disabled_categories', ['sqli', 'nosqli', 'scanner']);

    expect($this->validator->validate())->toBe([]);
});

it('accepts integer values provided as numeric strings (env style)', function () {
    config()->set('waf.paranoia_level', '2');
    config()->set('waf.block_confidence', '60');

    expect($this->validator->validate())->toBe([]);
});
