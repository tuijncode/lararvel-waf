<?php

it('ships a non-empty, valid pattern pack with no India-specific PII', function () {
    $pack = require __DIR__.'/../../config/waf-patterns.php';
    $patterns = $pack['custom'];

    expect($patterns)->not->toBeEmpty();

    $blocklist = ['aadhaar', 'ifsc', 'pan card', 'permanent account', 'india', 'rupee'];

    foreach ($patterns as $regex => $definition) {
        // Every regex compiles.
        expect(@preg_match($regex, ''))->not->toBeFalse("Invalid regex: {$regex}");

        $label = is_array($definition) ? $definition['label'] : $definition;

        // Severity, when given, is valid.
        if (is_array($definition) && isset($definition['severity'])) {
            expect($definition['severity'])->toBeIn(['critical', 'error', 'warning', 'notice']);
        }

        // No India-specific PII signatures.
        foreach ($blocklist as $term) {
            expect(strtolower($label))->not->toContain($term);
        }
    }
});
