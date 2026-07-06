<?php

use Tuijncode\LaravelWaf\Services\DdosMonitor;

it('trips once the request count passes the threshold', function () {
    config()->set('waf.ddos.threshold', 3);
    $monitor = new DdosMonitor;

    $client = '203.0.113.9';

    expect($monitor->tripped($client))->toBeFalse(); // 1
    expect($monitor->tripped($client))->toBeFalse(); // 2
    expect($monitor->tripped($client))->toBeFalse(); // 3
    expect($monitor->tripped($client))->toBeTrue();  // 4 > 3
});

it('counts each client independently', function () {
    config()->set('waf.ddos.threshold', 1);
    $monitor = new DdosMonitor;

    $monitor->tripped('198.51.100.1');
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
