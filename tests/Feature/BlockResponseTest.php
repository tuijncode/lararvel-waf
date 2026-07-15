<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Tuijncode\LaravelWaf\Events\RequestBlocked;

$attack = fn () => '/?q='.rawurlencode("' UNION SELECT * FROM users--");

beforeEach(function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 40);
});

it('returns the configured status and message on block', function () use ($attack) {
    config()->set('waf.block_response.status', 418);
    config()->set('waf.block_response.message', 'Blocked by WAF');

    $response = $this->get($attack(), ['User-Agent' => 'sqlmap/1.7']);

    $response->assertStatus(418)->assertSee('Blocked by WAF');
});

it('returns JSON to clients that expect it', function () use ($attack) {
    $response = $this->getJson($attack(), ['User-Agent' => 'sqlmap/1.7']);

    $response->assertStatus(403)->assertJson(['message' => 'Forbidden']);
});

it('forces JSON when always_json is set', function () use ($attack) {
    config()->set('waf.block_response.always_json', true);

    $this->get($attack(), ['User-Agent' => 'sqlmap/1.7'])
        ->assertStatus(403)
        ->assertJson(['message' => 'Forbidden']);
});

it('dispatches the RequestBlocked event when blocking', function () use ($attack) {
    Event::fake([RequestBlocked::class]);

    $this->get($attack(), ['User-Agent' => 'sqlmap/1.7'])->assertForbidden();

    Event::assertDispatched(RequestBlocked::class);
});

it('throttles RequestBlocked to once per finding under repeated blocks', function () use ($attack) {
    Event::fake([RequestBlocked::class]);

    // Every request is refused, but the event fires once per IP + signature per
    // dedup window — so listeners aren't drowned by a flood of identical blocks.
    $this->get($attack())->assertForbidden();
    $this->get($attack())->assertForbidden();
    $this->get($attack())->assertForbidden();

    Event::assertDispatchedTimes(RequestBlocked::class, 1);
});

it('records action_taken as blocked only when actually blocked', function () use ($attack) {
    $this->get($attack(), ['User-Agent' => 'sqlmap/1.7'])->assertForbidden();

    expect(DB::table('waf_logs')->value('action_taken'))->toBe('blocked');
});

it('records action_taken as logged when below the block threshold', function () {
    config()->set('waf.block_confidence', 95);

    // Open-redirect probe scores in the medium band — logged, not blocked.
    $this->get('/?next=//evil.example')->assertOk();

    expect(DB::table('waf_logs')->value('action_taken'))->toBe('logged');
});
