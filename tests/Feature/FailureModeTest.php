<?php

use Illuminate\Http\Request;
use Tuijncode\LaravelWaf\Services\InspectionResult;
use Tuijncode\LaravelWaf\Services\WafInspector;

$exploding = fn () => new class extends WafInspector
{
    public function handle(Request $request): ?InspectionResult
    {
        throw new RuntimeException('inspection exploded');
    }
};

it('fails open on an inspection error by default', function () use ($exploding) {
    $this->app->instance(WafInspector::class, $exploding());

    $this->get('/?q=hello')->assertOk()->assertSee('ok');
});

it('fails closed on an inspection error when configured', function () use ($exploding) {
    config()->set('waf.on_error', 'closed');
    $this->app->instance(WafInspector::class, $exploding());

    $this->get('/?q=hello')->assertStatus(503);
});
