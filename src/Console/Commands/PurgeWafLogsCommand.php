<?php

namespace Tuijncode\LaravelWaf\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class PurgeWafLogsCommand extends Command
{
    protected $signature = 'waf:purge {--days=30 : Age threshold in days}';

    protected $description = 'Prune firewall findings older than the given age';

    public function handle(): int
    {
        $days = max(0, (int) $this->option('days'));
        $horizon = now()->subDays($days);
        $table = config('waf.table_name', 'waf_logs');

        $total = DB::table($table)->where('created_at', '<', $horizon)->count();

        if ($total === 0) {
            $this->line("Nothing to prune — no findings predate {$days} day(s) ago.");

            return self::SUCCESS;
        }

        $confirmed = ! $this->input->isInteractive()
            || $this->confirm("Prune {$total} finding(s) older than {$days} day(s)?");

        if (! $confirmed) {
            $this->line('Aborted.');

            return self::SUCCESS;
        }

        // Clear the dependent exclusion rules first, then the findings — both
        // keyed off a DB-side subquery so a large purge never materialises
        // millions of ids in PHP memory.
        $this->cascadeExclusions($table, $horizon);

        $deleted = DB::table($table)->where('created_at', '<', $horizon)->delete();

        $this->info("Pruned {$deleted} finding(s).");

        return self::SUCCESS;
    }

    /**
     * Remove exclusion rules that referenced findings this purge is deleting,
     * selecting the doomed ids with a subquery rather than loading them.
     */
    private function cascadeExclusions(string $table, \DateTimeInterface $horizon): void
    {
        if (! Schema::hasTable('waf_exclusion_rules')) {
            return;
        }

        $gone = DB::table('waf_exclusion_rules')
            ->whereIn('source_log_id', fn ($query) => $query
                ->select('id')
                ->from($table)
                ->where('created_at', '<', $horizon))
            ->delete();

        if ($gone > 0) {
            $this->line("Also removed {$gone} exclusion rule(s) tied to pruned findings.");
        }
    }
}
