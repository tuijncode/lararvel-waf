<?php

it('trims whitespace around comma-separated whitelist env entries', function () {
    // "1.2.3.4, 5.6.7.8" is how people naturally write these lists; without
    // trimming, the space-prefixed entries silently never match.
    $_ENV['WAF_WHITELISTED_IPS'] = ' 203.0.113.5 , 198.51.100.7,, ';
    $_ENV['WAF_WHITELISTED_AGENTS'] = ' UptimeRobot , Pingdom ';

    try {
        $config = require dirname(__DIR__, 2).'/config/waf.php';
    } finally {
        unset($_ENV['WAF_WHITELISTED_IPS'], $_ENV['WAF_WHITELISTED_AGENTS']);
    }

    expect($config['whitelisted_ips'])->toBe(['203.0.113.5', '198.51.100.7'])
        ->and($config['whitelisted_agents'])->toBe(['UptimeRobot', 'Pingdom']);
});

it('parses empty whitelist env values to empty lists', function () {
    $_ENV['WAF_WHITELISTED_IPS'] = '';

    try {
        $config = require dirname(__DIR__, 2).'/config/waf.php';
    } finally {
        unset($_ENV['WAF_WHITELISTED_IPS']);
    }

    expect($config['whitelisted_ips'])->toBe([]);
});
