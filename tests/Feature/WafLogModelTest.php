<?php

use Tuijncode\LaravelWaf\Models\WafLog;

function seedModelLog(string $ip, $createdAt): void
{
    WafLog::insert([
        'ip_address' => $ip,
        'url' => '/',
        'type' => '[942100] test',
        'category' => 'sqli',
        'threat_level' => 'critical',
        'created_at' => $createdAt,
        'updated_at' => $createdAt,
    ]);
}

it('reads findings through the configured table', function () {
    seedModelLog('203.0.113.1', now());

    expect(WafLog::count())->toBe(1)
        ->and(WafLog::first()->ip_address)->toBe('203.0.113.1')
        ->and(WafLog::first()->confidence_score)->toBeInt();
});

it('prunes findings past the retention horizon', function () {
    config()->set('waf.retention.enabled', true);
    config()->set('waf.retention.days', 30);

    seedModelLog('203.0.113.1', now()->subDays(60)); // stale
    seedModelLog('203.0.113.2', now()->subDay());    // fresh

    (new WafLog)->pruneAll();

    expect(WafLog::count())->toBe(1)
        ->and(WafLog::first()->ip_address)->toBe('203.0.113.2');
});

it('prunes nothing while retention is disabled', function () {
    config()->set('waf.retention.enabled', false);

    seedModelLog('203.0.113.1', now()->subDays(60));

    (new WafLog)->pruneAll();

    expect(WafLog::count())->toBe(1);
});
