<?php

namespace Tuijncode\LaravelWaf\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;

/**
 * Read-side Eloquent model over the `waf_logs` table.
 *
 * Findings are written with the query builder (so they work with or without
 * this model, queued or inline), but this gives host applications a first-class
 * model for querying and reporting — and, via Prunable, retention through
 * Laravel's own `model:prune` scheduler.
 *
 * @property int $id
 * @property ?string $event_id
 * @property string $ip_address
 * @property string $type
 * @property string $category
 * @property int $confidence_score
 * @property string $action_taken
 */
class WafLog extends Model
{
    use Prunable;

    protected $guarded = [];

    protected $casts = [
        'anomaly_score' => 'integer',
        'confidence_score' => 'integer',
        'user_id' => 'integer',
    ];

    public function getTable(): string
    {
        return config('waf.table_name', 'waf_logs');
    }

    /**
     * Prune findings older than the configured retention horizon. Only takes
     * effect once retention is enabled; otherwise nothing is eligible.
     */
    public function prunable(): Builder
    {
        if (! config('waf.retention.enabled', false)) {
            // An always-false constraint: nothing is prunable.
            return static::query()->whereRaw('1 = 0');
        }

        $days = (int) config('waf.retention.days', 90);

        return static::query()->where('created_at', '<', now()->subDays($days));
    }
}
