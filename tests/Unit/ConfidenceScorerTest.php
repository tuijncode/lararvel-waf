<?php

use Tuijncode\LaravelWaf\Rules\SignatureMatch;
use Tuijncode\LaravelWaf\Services\ConfidenceScorer;

beforeEach(fn () => $this->scorer = new ConfidenceScorer);

function match_(string $severity, string $context = 'query'): SignatureMatch
{
    return new SignatureMatch('id', 'cat', 'name', 'desc', $severity, $context, 'x');
}

it('returns a clean zero for no signals', function () {
    expect($this->scorer->calculate([]))->toBe(['score' => 0, 'label' => 'none', 'anomaly_score' => 0]);
});

it('sums the anomaly score from matched severities', function () {
    $result = $this->scorer->calculate([match_('critical'), match_('warning')]);

    // critical (5) + warning (3) = 8
    expect($result['anomaly_score'])->toBe(8);
});

it('adds a breadth bonus for multiple distinct matches', function () {
    $one = $this->scorer->calculate([match_('error')]);
    $three = $this->scorer->calculate([match_('error'), match_('error', 'body'), match_('error', 'body')]);

    expect($three['score'])->toBeGreaterThan($one['score']);
});

it('lifts the score for scanner, bot and flood signals', function () {
    $base = $this->scorer->calculate([match_('warning')])['score'];

    expect($this->scorer->calculate([match_('warning')], isScanner: true)['score'])->toBeGreaterThan($base)
        ->and($this->scorer->calculate([match_('warning')], isBot: true)['score'])->toBeGreaterThan($base)
        ->and($this->scorer->calculate([match_('warning')], isDdos: true)['score'])->toBeGreaterThan($base);
});

it('scores a signal-only request (scanner, no rule match)', function () {
    $result = $this->scorer->calculate([], isScanner: true);

    expect($result['score'])->toBeGreaterThan(0)
        ->and($result['anomaly_score'])->toBe(0);
});

it('never leaves the 0-100 range', function () {
    $huge = array_fill(0, 20, match_('critical'));
    $result = $this->scorer->calculate($huge, isScanner: true, isBot: true, isDdos: true);

    expect($result['score'])->toBeLessThanOrEqual(100)->toBeGreaterThanOrEqual(0);
});

it('maps scores onto labels', function () {
    expect($this->scorer->label(0))->toBe('none')
        ->and($this->scorer->label(10))->toBe('low')
        ->and($this->scorer->label(40))->toBe('medium')
        ->and($this->scorer->label(65))->toBe('high')
        ->and($this->scorer->label(90))->toBe('critical');
});
