<?php

namespace Tuijncode\LaravelWaf\Console\Commands;

use Illuminate\Console\Command;
use Tuijncode\LaravelWaf\Services\CorrelationAnalyzer;

class WafCorrelateCommand extends Command
{
    protected $signature = 'waf:correlate
                            {--coordinated-window=15 : Minutes for coordinated-attack detection}
                            {--campaign-hours=24 : Hours for campaign detection}
                            {--rapid-window=5 : Minutes for rapid-attacker detection}';

    protected $description = 'Correlate WAF findings to surface distributed / coordinated attacks';

    public function handle(CorrelationAnalyzer $analyzer): int
    {
        $coordinated = $analyzer->coordinatedAttacks((int) $this->option('coordinated-window'));
        $campaigns = $analyzer->campaigns((int) $this->option('campaign-hours'));
        $rapid = $analyzer->rapidAttackers((int) $this->option('rapid-window'));

        if (! $coordinated && ! $campaigns && ! $rapid) {
            $this->info('No correlated attack activity detected.');

            return self::SUCCESS;
        }

        if ($coordinated) {
            $this->line('<comment>Coordinated attacks (one target, many IPs)</comment>');
            $this->table(['URL', 'IPs', 'Hits', 'First', 'Last'], array_map(fn (array $r) => [
                $r['url'], $r['ips'], $r['hits'], $r['first_seen'], $r['last_seen'],
            ], $coordinated));
        }

        if ($campaigns) {
            $this->newLine();
            $this->line('<comment>Campaigns (one attack class, many IPs)</comment>');
            $this->table(['Category', 'IPs', 'Hits', 'First', 'Last'], array_map(fn (array $r) => [
                $r['category'], $r['ips'], $r['hits'], $r['first_seen'], $r['last_seen'],
            ], $campaigns));
        }

        if ($rapid) {
            $this->newLine();
            $this->line('<comment>Rapid attackers (one IP, many findings)</comment>');
            $this->table(['IP', 'Hits', 'Types', 'First', 'Last'], array_map(fn (array $r) => [
                $r['ip_address'], $r['hits'], $r['types'], $r['first_seen'], $r['last_seen'],
            ], $rapid));
        }

        return self::SUCCESS;
    }
}
