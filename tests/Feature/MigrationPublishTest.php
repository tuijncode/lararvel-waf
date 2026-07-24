<?php

use Tuijncode\LaravelWaf\WafServiceProvider;

/**
 * Every migration file this test may leave behind, so cleanup can't touch the
 * testbench skeleton's own migrations.
 */
function wafMigrationFiles(): array
{
    return array_merge(
        glob(database_path('migrations/*_create_waf_logs_table.php')) ?: [],
        glob(database_path('migrations/*_create_waf_exclusion_rules_table.php')) ?: [],
        glob(database_path('migrations/*_upgrade_waf_logs_table.php')) ?: [],
    );
}

beforeEach(function () {
    foreach (wafMigrationFiles() as $file) {
        unlink($file);
    }
});

afterEach(function () {
    foreach (wafMigrationFiles() as $file) {
        unlink($file);
    }
});

it('re-publishing migrations does not mint a timestamped duplicate', function () {
    // Simulate an install that published on an earlier day.
    $existing = database_path('migrations/2024_01_01_000000_create_waf_logs_table.php');
    file_put_contents($existing, '<?php // previously published');

    // Publish targets are resolved at boot; re-boot the provider so it sees
    // the already-published file, as a fresh process would.
    (new WafServiceProvider($this->app))->boot();

    $this->artisan('vendor:publish', ['--tag' => 'waf-migrations'])->run();

    // The pre-existing migration is kept (and not duplicated under a fresh
    // timestamp); the one that was never published is created normally.
    expect(glob(database_path('migrations/*_create_waf_logs_table.php')))->toBe([$existing])
        ->and(glob(database_path('migrations/*_create_waf_exclusion_rules_table.php')))->toHaveCount(1);
});

it('publishes all migrations on a fresh install', function () {
    (new WafServiceProvider($this->app))->boot();

    $this->artisan('vendor:publish', ['--tag' => 'waf-migrations'])->run();

    expect(glob(database_path('migrations/*_create_waf_logs_table.php')))->toHaveCount(1)
        ->and(glob(database_path('migrations/*_create_waf_exclusion_rules_table.php')))->toHaveCount(1);
});
