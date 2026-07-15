<?php

use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Services\DdosMonitor;

it('trips once the request count passes the threshold', function () {
    config()->set('waf.ddos.threshold', 3);
    $monitor = new DdosMonitor;

    $client = '203.0.113.9';

    foreach (range(1, 3) as $i) {
        $monitor->hit($client);
        expect($monitor->tripped($client))->toBeFalse();
    }

    $monitor->hit($client); // 4 > 3
    expect($monitor->tripped($client))->toBeTrue();
});

it('checks the budget without counting a hit', function () {
    config()->set('waf.ddos.threshold', 1);
    $monitor = new DdosMonitor;

    // tripped() is read-only: asking never advances the counter.
    foreach (range(1, 5) as $i) {
        expect($monitor->tripped('198.51.100.7'))->toBeFalse();
    }
});

it('counts each client independently', function () {
    config()->set('waf.ddos.threshold', 1);
    $monitor = new DdosMonitor;

    $monitor->hit('198.51.100.1');
    $monitor->hit('198.51.100.1');

    expect($monitor->tripped('198.51.100.1'))->toBeTrue()
        ->and($monitor->tripped('198.51.100.2'))->toBeFalse(); // fresh client
});

it('exposes its configured ceiling and window', function () {
    config()->set('waf.ddos.threshold', 42);
    config()->set('waf.ddos.window', 30);

    $monitor = new DdosMonitor;

    expect($monitor->ceiling())->toBe(42)
        ->and($monitor->windowSeconds())->toBe(30);
});

it('lets explicit constructor arguments win over the config', function () {
    config()->set('waf.ddos.threshold', 300);

    $monitor = new DdosMonitor(ceiling: 5, windowSeconds: 10);

    expect($monitor->ceiling())->toBe(5)
        ->and($monitor->windowSeconds())->toBe(10);
});

it('raises the flood signal end to end once the threshold is passed', function () {
    config()->set('waf.ddos.threshold', 2);

    $this->get('/?q=hello')->assertOk();
    $this->get('/?q=hello')->assertOk();
    $this->get('/?q=hello')->assertOk(); // 3 > 2

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('ddos');
});
