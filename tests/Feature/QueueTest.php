<?php

use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Jobs\StoreWafLog;

it('dispatches the store job instead of inserting inline when queueing is enabled', function () {
    config()->set('waf.queue.enabled', true);
    config()->set('waf.queue.queue', 'security');
    Bus::fake();

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    // The insert is deferred to the queue, so nothing is written synchronously.
    expect(DB::table('waf_logs')->count())->toBe(0);

    Bus::assertDispatched(StoreWafLog::class);
});

it('inserts inline when queueing is disabled', function () {
    config()->set('waf.queue.enabled', false);
    Bus::fake();

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
    Bus::assertNotDispatched(StoreWafLog::class);
});
