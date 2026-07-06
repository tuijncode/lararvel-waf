<?php

use Illuminate\Support\Facades\DB;

it('logs a repeated identical threat only once within the dedup window', function () {
    $q = '/?q='.rawurlencode("' UNION SELECT * FROM users--");

    $this->get($q)->assertOk();
    $this->get($q)->assertOk();
    $this->get($q)->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('logs distinct threats separately', function () {
    $this->get('/?q='.rawurlencode("' UNION SELECT 1--"))->assertOk();
    $this->get('/?q='.rawurlencode('<script>alert(1)</script>'))->assertOk();

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
