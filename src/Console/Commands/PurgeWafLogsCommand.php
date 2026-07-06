<?php

namespace Tuijncode\LaravelWaf\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
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

        $stale = DB::table($table)->where('created_at', '<', $horizon);
        $total = $stale->count();

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

        $doomed = $stale->pluck('id');
        $this->cascadeExclusions($doomed);

        DB::table($table)->whereIn('id', $doomed)->delete();

        $this->info("Pruned {$total} finding(s).");

        return self::SUCCESS;
    }

    /**
     * Tidy up exclusion rules that referenced findings we are about to remove.
     *
     * @param  Collection<int, int>  $logIds
     */
    private function cascadeExclusions(Collection $logIds): void
    {
        if ($logIds->isEmpty() || ! Schema::hasTable('waf_exclusion_rules')) {
            return;
        }

        $gone = DB::table('waf_exclusion_rules')
            ->whereIn('source_log_id', $logIds)
            ->delete();

        if ($gone > 0) {
            $this->line("Also removed {$gone} exclusion rule(s) tied to pruned findings.");
        }
    }
}
