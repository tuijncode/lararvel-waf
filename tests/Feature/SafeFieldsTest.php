<?php

use Illuminate\Support\Facades\DB;

it('does not flag a payload carried in a safe field', function () {
    config()->set('waf.safe_fields', ['content']);

    $this->post('/', [
        'content' => '<script>alert(1)</script>',
        'title' => 'a normal title',
    ])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('still flags a payload in a non-safe field alongside a safe one', function () {
    config()->set('waf.safe_fields', ['content']);

    $this->post('/', [
        'content' => 'harmless rich text',
        'title' => '<script>alert(1)</script>',
    ])->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('xss');
});

it('excludes a nested field by dot-notation', function () {
    config()->set('waf.safe_fields', ['post.body']);

    $this->post('/', [
        'post' => ['body' => '<script>alert(1)</script>', 'title' => 'ok'],
    ])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('excludes wildcard field paths', function () {
    config()->set('waf.safe_fields', ['blocks.*.html']);

    $this->post('/', [
        'blocks' => [
            ['html' => '<script>alert(1)</script>'],
            ['html' => '<iframe src=x>'],
        ],
    ])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('excludes everything nested beneath a bare field name', function () {
    config()->set('waf.safe_fields', ['content']);

    $this->post('/', [
        'content' => ['nested' => '<script>alert(1)</script>'],
    ])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('excludes a safe field carried in the query string', function () {
    config()->set('waf.safe_fields', ['q']);

    $this->get('/?q='.rawurlencode('<script>alert(1)</script>'))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('still scans the raw body when no safe fields are configured', function () {
    // Baseline: the same payload without safe_fields is caught.
    $this->post('/', ['content' => '<script>alert(1)</script>'])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});
