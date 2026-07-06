<?php

use Tuijncode\LaravelWaf\Rules\SignatureMatch;
use Tuijncode\LaravelWaf\Services\InspectionResult;

function hit(string $id, string $severity, string $category = 'sqli'): SignatureMatch
{
    return new SignatureMatch(
        id: $id,
        category: $category,
        name: 'Test',
        description: "Rule {$id}",
        severity: $severity,
        context: 'query',
        matched: 'x',
    );
}

it('reports no threat for an empty result', function () {
    $result = new InspectionResult;

    expect($result->isThreat())->toBeFalse()
        ->and($result->summary())->toBe('No threat')
        ->and($result->ruleIds())->toBe([]);
});

it('summarises using the first matched rule', function () {
    $result = new InspectionResult(matches: [hit('942110', 'critical'), hit('941100', 'error', 'xss')]);

    expect($result->isThreat())->toBeTrue()
        ->and($result->summary())->toContain('942110')
        ->and($result->ruleIds())->toBe(['942110', '941100']);
});

it('takes the highest severity across matches', function () {
    $result = new InspectionResult(matches: [hit('1', 'notice'), hit('2', 'critical'), hit('3', 'warning')]);

    expect($result->severity())->toBe('critical');
});

it('promotes scanner and ddos findings to critical severity', function () {
    $scanner = new InspectionResult(isScanner: true, scannerName: 'SQLMap');
    $flood = new InspectionResult(isDdos: true);

    expect($scanner->severity())->toBe('critical')
        ->and($scanner->summary())->toContain('SQLMap')
        ->and($flood->severity())->toBe('critical')
        ->and($flood->isThreat())->toBeTrue();
});

it('deduplicates rule ids', function () {
    $result = new InspectionResult(matches: [hit('942110', 'critical'), hit('942110', 'critical')]);

    expect($result->ruleIds())->toBe(['942110']);
});
