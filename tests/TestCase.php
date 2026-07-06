<?php

namespace Tuijncode\LaravelWaf\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;
use Tuijncode\LaravelWaf\WafServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createWafLogsTable();
        $this->createWafExclusionRulesTable();

        // A catch-all route guarded by the WAF middleware so feature tests can
        // fire attack payloads at any path.
        Route::middleware('waf')->any('/{path?}', fn () => 'ok')->where('path', '.*');
    }

    protected function getPackageProviders($app): array
    {
        return [WafServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // The array cache supports atomic increments (needed by DDoS + dedup).
        $app['config']->set('cache.default', 'array');

        $app['config']->set('waf.enabled', true);
        $app['config']->set('waf.enabled_environments', null);
        $app['config']->set('waf.mode', 'detection');
        $app['config']->set('waf.table_name', 'waf_logs');
        $app['config']->set('waf.whitelisted_ips', []);
        $app['config']->set('waf.min_confidence', 10);
    }

    protected function createWafLogsTable(): void
    {
        Schema::create('waf_logs', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address')->index();
            $table->string('method', 10)->nullable();
            $table->text('url');
            $table->string('user_agent', 500)->nullable();
            $table->text('type');
            $table->string('category', 30)->index();
            $table->string('rule_ids')->nullable();
            $table->text('payload')->nullable();
            $table->string('threat_level', 20)->default('notice')->index();
            $table->unsignedSmallInteger('anomaly_score')->default(0);
            $table->unsignedTinyInteger('confidence_score')->default(0)->index();
            $table->string('confidence_label', 20)->default('none');
            $table->string('action_taken', 20)->default('logged');
            $table->unsignedBigInteger('user_id')->nullable()->index();
            $table->timestamps();
        });
    }

    protected function createWafExclusionRulesTable(): void
    {
        Schema::create('waf_exclusion_rules', function (Blueprint $table) {
            $table->id();
            $table->string('match_label');
            $table->string('path_glob')->nullable();
            $table->unsignedBigInteger('source_log_id')->nullable();
            $table->unsignedBigInteger('created_by_user_id')->nullable();
            $table->text('reason')->nullable();
            $table->boolean('is_active')->default(true)->index();
            $table->timestamps();
        });
    }
}
