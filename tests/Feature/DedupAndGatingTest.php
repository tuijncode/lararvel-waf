<?php

use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Services\CorrelationAnalyzer;

it('logs a repeated identical threat only once within the dedup window', function () {
    $q = '/?q='.rawurlencode("' UNION SELECT * FROM users--");

    $this->get($q)->assertOk();
    $this->get($q)->assertOk();
    $this->get($q)->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('bumps the hit counter on a deduplicated finding instead of dropping it', function () {
    config()->set('waf.dedup_flush_seconds', 0); // write every bump through, exact
    $q = '/?q='.rawurlencode("' UNION SELECT * FROM users--");

    $this->get($q)->assertOk();
    $this->get($q)->assertOk();
    $this->get($q)->assertOk();

    $log = DB::table('waf_logs')->sole();
    expect((int) $log->hit_count)->toBe(3);
});

it('surfaces a single-attack flood as a rapid attacker via hit_count', function () {
    config()->set('waf.dedup_flush_seconds', 0);
    $q = '/?q='.rawurlencode("' UNION SELECT * FROM users--");

    // 12 identical hits collapse to one row (hit_count 12). Counting rows would
    // see 1 and miss it; SUM(hit_count) surfaces the volume.
    for ($i = 0; $i < 12; $i++) {
        $this->get($q)->assertOk();
    }

    expect(DB::table('waf_logs')->count())->toBe(1);

    $found = app(CorrelationAnalyzer::class)->rapidAttackers(windowMinutes: 5, minHits: 10);

    expect($found)->toHaveCount(1)
        ->and($found[0]['ip_address'])->toBe('127.0.0.1')
        ->and((int) $found[0]['hits'])->toBe(12);
});

it('coalesces hit_count writes when a flush interval is set', function () {
    config()->set('waf.dedup_flush_seconds', 300); // effectively one flush per burst
    $q = '/?q='.rawurlencode("' UNION SELECT * FROM users--");

    for ($i = 0; $i < 12; $i++) {
        $this->get($q)->assertOk();
    }

    // Still one row, but the counter isn't written per request: the bumps are
    // held in the cache and only partially flushed, so the stored count trails
    // the true volume (eventually consistent) rather than costing 11 UPDATEs.
    $log = DB::table('waf_logs')->sole();
    expect((int) $log->hit_count)->toBeLessThan(12)
        ->and((int) $log->hit_count)->toBeGreaterThanOrEqual(1);
});

it('does not tally duplicates under queueing (hit_count stays 1)', function () {
    config()->set('queue.default', 'sync');
    config()->set('waf.queue.enabled', true);

    $q = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($q)->assertOk();
    $this->get($q)->assertOk();
    $this->get($q)->assertOk();

    // The row id isn't known synchronously under queueing, so later duplicates
    // aren't counted — one row, hit_count 1.
    $log = DB::table('waf_logs')->sole();
    expect((int) $log->hit_count)->toBe(1);
});

it('logs distinct threats separately', function () {
    $this->get('/?q='.rawurlencode("' UNION SELECT 1--"))->assertOk();
    $this->get('/?q='.rawurlencode('<script>alert(1)</script>'))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(2);
});

it('collapses the same attack across paths by default', function () {
    $q = 'q='.rawurlencode("' UNION SELECT * FROM users--");

    $this->get('/alpha?'.$q)->assertOk();
    $this->get('/beta?'.$q)->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('keeps the same attack per path when dedup_include_path is on', function () {
    config()->set('waf.dedup_include_path', true);
    $q = 'q='.rawurlencode("' UNION SELECT * FROM users--");

    $this->get('/alpha?'.$q)->assertOk();
    $this->get('/beta?'.$q)->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(2);
});

it('drops findings below the minimum confidence', function () {
    config()->set('waf.min_confidence', 99);

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('keeps findings at or above the minimum confidence', function () {
    config()->set('waf.min_confidence', 1);

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});
