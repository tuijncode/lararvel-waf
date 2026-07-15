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

it('flags an out-of-range dedup flush interval', function () {
    config()->set('waf.dedup_flush_seconds', -1);

    expect(implode(' ', $this->validator->validate()))->toContain('waf.dedup_flush_seconds');
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

it('flags an invalid on_error mode', function () {
    config()->set('waf.on_error', 'colsed');

    expect($this->validator->validate())->toContain(
        "waf.on_error must be one of [open, closed], got 'colsed'."
    );
});

it('flags a non-array enabled_environments', function () {
    config()->set('waf.enabled_environments', 'production');

    expect(implode(' ', $this->validator->validate()))->toContain('waf.enabled_environments');
});

it('flags a non-positive auto_ban setting', function () {
    config()->set('waf.auto_ban.max_blocks', 0);

    expect(implode(' ', $this->validator->validate()))->toContain('waf.auto_ban.max_blocks');
});

it('flags an unparsable custom pattern regex', function () {
    config()->set('waf.custom_patterns', ['/broken(/' => 'Broken']);

    expect(implode(' ', $this->validator->validate()))->toContain('not a valid regular expression');
});

it('flags an unknown custom pattern severity', function () {
    config()->set('waf.custom_patterns', [
        '/ok/i' => ['label' => 'X', 'severity' => 'criticl'],
    ]);

    expect(implode(' ', $this->validator->validate()))->toContain("unknown severity 'criticl'");
});

it('flags an unknown custom pattern target surface', function () {
    config()->set('waf.custom_patterns', [
        '/ok/i' => ['label' => 'X', 'targets' => ['querry']],
    ]);

    expect(implode(' ', $this->validator->validate()))->toContain("unknown surface 'querry'");
});

it('flags an unknown custom pattern validator', function () {
    config()->set('waf.custom_patterns', [
        '/ok/i' => ['label' => 'X', 'validator' => 'moon-phase'],
    ]);

    expect(implode(' ', $this->validator->validate()))->toContain("unknown validator 'moon-phase'");
});

it('accepts the built-in luhn validator', function () {
    config()->set('waf.custom_patterns', [
        '/ok/i' => ['label' => 'X', 'validator' => 'luhn'],
    ]);

    expect($this->validator->validate())->toBe([]);
});
