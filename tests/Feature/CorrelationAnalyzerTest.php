<?php

use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Services\CorrelationAnalyzer;

function record(array $overrides = []): void
{
    DB::table('waf_logs')->insert(array_merge([
        'ip_address' => '10.0.0.1',
        'method' => 'GET',
        'url' => 'http://localhost/login',
        'type' => '[942100] SQLi',
        'category' => 'sqli',
        'threat_level' => 'critical',
        'confidence_score' => 60,
        'confidence_label' => 'high',
        'action_taken' => 'logged',
        'created_at' => now(),
        'updated_at' => now(),
    ], $overrides));
}

beforeEach(fn () => $this->analyzer = new CorrelationAnalyzer);

it('detects a coordinated attack: one URL, many IPs', function () {
    foreach (['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4'] as $ip) {
        record(['ip_address' => $ip, 'url' => 'http://localhost/wp-login.php']);
    }
    record(['ip_address' => '9.9.9.9', 'url' => 'http://localhost/other']); // not coordinated

    $found = $this->analyzer->coordinatedAttacks(windowMinutes: 15, minIps: 3);

    expect($found)->toHaveCount(1)
        ->and($found[0]['url'])->toBe('http://localhost/wp-login.php')
        ->and((int) $found[0]['ips'])->toBe(4);
});

it('detects a campaign: one category, many IPs', function () {
    foreach (['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5'] as $ip) {
        record(['ip_address' => $ip, 'category' => 'xss', 'url' => "http://localhost/p/{$ip}"]);
    }

    $found = $this->analyzer->campaigns(windowHours: 24, minIps: 5);

    expect($found)->toHaveCount(1)
        ->and($found[0]['category'])->toBe('xss')
        ->and((int) $found[0]['ips'])->toBe(5);
});

it('detects a rapid attacker: one IP, many findings', function () {
    for ($i = 0; $i < 12; $i++) {
        record(['ip_address' => '6.6.6.6', 'type' => "[94210{$i}] probe {$i}"]);
    }
    record(['ip_address' => '7.7.7.7']); // below threshold

    $found = $this->analyzer->rapidAttackers(windowMinutes: 5, minHits: 10);

    expect($found)->toHaveCount(1)
        ->and($found[0]['ip_address'])->toBe('6.6.6.6')
        ->and((int) $found[0]['hits'])->toBe(12);
});

it('counts volume via hit_count, not just distinct rows', function () {
    // A single deduplicated finding that stands for 15 requests.
    record(['ip_address' => '6.6.6.6', 'hit_count' => 15]);

    $found = $this->analyzer->rapidAttackers(windowMinutes: 5, minHits: 10);

    expect($found)->toHaveCount(1)
        ->and((int) $found[0]['hits'])->toBe(15);
});

it('ignores activity outside the window', function () {
    foreach (['1.1.1.1', '2.2.2.2', '3.3.3.3'] as $ip) {
        record(['ip_address' => $ip, 'created_at' => now()->subHours(2), 'updated_at' => now()->subHours(2)]);
    }

    expect($this->analyzer->coordinatedAttacks(windowMinutes: 15, minIps: 3))->toBe([]);
});

it('summarises the correlation signals', function () {
    foreach (['1.1.1.1', '2.2.2.2', '3.3.3.3'] as $ip) {
        record(['ip_address' => $ip, 'url' => 'http://localhost/target']);
    }

    expect($this->analyzer->summary())
        ->toHaveKeys(['coordinated_attacks', 'campaigns', 'rapid_attackers'])
        ->and($this->analyzer->summary()['coordinated_attacks'])->toBe(1);
});

it('reports nothing via the command when there is no correlated activity', function () {
    $this->artisan('waf:correlate')
        ->expectsOutputToContain('No correlated attack activity detected.')
        ->assertSuccessful();
});
