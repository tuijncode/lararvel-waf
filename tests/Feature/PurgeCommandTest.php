<?php

use Illuminate\Support\Facades\DB;

function seedLog(string $type, DateTimeInterface $createdAt): int
{
    return DB::table('waf_logs')->insertGetId([
        'ip_address' => '10.0.0.1',
        'method' => 'GET',
        'url' => 'http://localhost/',
        'type' => $type,
        'category' => 'sqli',
        'threat_level' => 'critical',
        'confidence_score' => 50,
        'confidence_label' => 'medium',
        'created_at' => $createdAt,
        'updated_at' => $createdAt,
    ]);
}

it('purges logs older than the given number of days', function () {
    seedLog('old', now()->subDays(100));
    seedLog('recent', now()->subDays(5));

    $this->artisan('waf:purge --days=90')
        ->expectsConfirmation('Prune 1 finding(s) older than 90 day(s)?', 'yes')
        ->expectsOutputToContain('Pruned 1 finding(s).')
        ->assertSuccessful();

    expect(DB::table('waf_logs')->count())->toBe(1)
        ->and(DB::table('waf_logs')->value('type'))->toBe('recent');
});

it('removes exclusion rules orphaned by a purge', function () {
    $oldId = seedLog('old', now()->subDays(100));

    DB::table('waf_exclusion_rules')->insert([
        'match_label' => 'old',
        'source_log_id' => $oldId,
        'is_active' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $this->artisan('waf:purge --days=90')
        ->expectsConfirmation('Prune 1 finding(s) older than 90 day(s)?', 'yes')
        ->assertSuccessful();

    expect(DB::table('waf_exclusion_rules')->count())->toBe(0);
});

it('reports when nothing needs purging', function () {
    seedLog('recent', now()->subDays(5));

    $this->artisan('waf:purge --days=90')
        ->expectsOutputToContain('Nothing to prune — no findings predate 90 day(s) ago.')
        ->assertSuccessful();

    expect(DB::table('waf_logs')->count())->toBe(1);
});
