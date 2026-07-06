<?php

namespace Tuijncode\LaravelWaf\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\DB;

/**
 * Writes a single firewall finding to storage away from the request path.
 *
 * Dispatched only when queueing is switched on, so a slow database never bleeds
 * into response times on a route that is under attack.
 */
class StoreWafLog implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    /**
     * Give up after a handful of attempts; a lost finding must not wedge a queue.
     */
    public int $tries = 5;

    /**
     * @param  array<string, mixed>  $row
     */
    public function __construct(private readonly array $row) {}

    public function handle(): void
    {
        DB::table(config('waf.table_name', 'waf_logs'))->insert($this->row);
    }

    public function backoff(): array
    {
        return [5, 15, 60];
    }
}
