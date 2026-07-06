<?php

use Tuijncode\LaravelWaf\Rules\CoreRuleSet;
use Tuijncode\LaravelWaf\Rules\Signature;
use Tuijncode\LaravelWaf\Rules\SignatureMatch;
use Tuijncode\LaravelWaf\Services\ConfidenceScorer;

it('ships with 30 or more detection patterns', function () {
    expect(count(CoreRuleSet::rules()))->toBeGreaterThanOrEqual(30);
});

it('returns typed Signature objects', function () {
    expect(CoreRuleSet::rules())->each->toBeInstanceOf(Signature::class);
});

it('has a valid regex and unique id for every rule', function () {
    $ids = [];

    foreach (CoreRuleSet::rules() as $rule) {
        expect(@preg_match($rule->regex, ''))->not->toBeFalse("Invalid regex for rule {$rule->id}");
        expect($rule->severity)->toBeIn(['critical', 'error', 'warning', 'notice']);
        expect($rule->paranoia)->toBeGreaterThanOrEqual(1);
        expect($ids)->not->toContain($rule->id);
        $ids[] = $rule->id;
    }
});

it('scores a single critical match into the high-confidence band', function () {
    $scorer = new ConfidenceScorer;

    $result = $scorer->calculate([
        new SignatureMatch('942100', 'sqli', 'SQLi', 'x', 'critical', 'query', 'x'),
    ]);

    expect($result['score'])->toBeGreaterThanOrEqual(35)
        ->and($result['anomaly_score'])->toBe(5)
        ->and($result['label'])->toBeIn(['medium', 'high', 'critical']);
});

it('returns a zero score for a clean request', function () {
    $scorer = new ConfidenceScorer;

    expect($scorer->calculate([])['score'])->toBe(0)
        ->and($scorer->calculate([])['label'])->toBe('none');
});
