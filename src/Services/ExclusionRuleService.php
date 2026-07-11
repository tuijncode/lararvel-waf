<?php

namespace Tuijncode\LaravelWaf\Services;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Allow-list for tuning out noise.
 *
 * Operators register signatures they trust (by a substring of the finding
 * label and, optionally, a path glob). When a later finding matches one of
 * those entries it is flagged as an accepted false positive rather than a live
 * threat. The active set is memoised briefly to spare the database on every
 * request.
 */
class ExclusionRuleService
{
    private const TABLE = 'waf_exclusion_rules';

    private const CACHE_BUCKET = 'laravel-waf.exclusions.active';

    /**
     * Decide whether a finding should be treated as an accepted false positive.
     */
    public function accepts(string $signature, string $path): bool
    {
        $path = trim((string) parse_url($path, PHP_URL_PATH), '/');

        return $this->active()->contains(function (object $entry) use ($signature, $path): bool {
            if (! str_contains($signature, $entry->match_label)) {
                return false;
            }

            return blank($entry->path_glob) || fnmatch($entry->path_glob, $path);
        });
    }

    /**
     * Promote a previously logged finding into a standing exclusion.
     */
    public function acceptFromLog(int $logId, ?int $userId = null, ?string $reason = null): ?object
    {
        $finding = DB::table(config('waf.table_name', 'waf_logs'))->find($logId);

        if ($finding === null) {
            return null;
        }

        $finding = (object) $finding;

        // The bracketed rule id (e.g. "[942110]") is the most precise handle;
        // fall back to the whole label when the shape is unexpected.
        $label = preg_match('/^\[([^\]]+)\]/', $finding->type, $hit)
            ? $hit[1]
            : $finding->type;

        $newId = DB::table(self::TABLE)->insertGetId([
            'match_label' => $label,
            'path_glob' => trim((string) parse_url($finding->url, PHP_URL_PATH), '/') ?: null,
            'source_log_id' => $logId,
            'created_by_user_id' => $userId,
            'reason' => $reason,
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->refresh();

        return DB::table(self::TABLE)->find($newId);
    }

    public function drop(int $ruleId): bool
    {
        $removed = DB::table(self::TABLE)->where('id', $ruleId)->delete() > 0;

        if ($removed) {
            $this->refresh();
        }

        return $removed;
    }

    /**
     * @return Collection<int, \stdClass>
     */
    public function listing(): Collection
    {
        if (! $this->installed()) {
            return collect();
        }

        return DB::table(self::TABLE)->latest()->get();
    }

    public function refresh(): void
    {
        Cache::forget(self::CACHE_BUCKET);
    }

    /**
     * @return Collection<int, \stdClass>
     */
    private function active(): Collection
    {
        // Cache plain arrays, never objects. Laravel's cache stores unserialize
        // with an `allowed_classes` restriction (cache.serializable_classes,
        // which defaults to false in Laravel 12+), so a cached Collection or
        // stdClass would come back as __PHP_Incomplete_Class and make this
        // method throw — silently disabling the WAF. Rebuild the objects on read.
        $rows = Cache::remember(self::CACHE_BUCKET, now()->addMinutes(10), function (): array {
            return $this->installed()
                ? DB::table(self::TABLE)->where('is_active', true)->get()
                    ->map(static fn (object $row): array => (array) $row)->all()
                : [];
        });

        return collect($rows)->map(static fn (array $row): object => (object) $row);
    }

    private function installed(): bool
    {
        try {
            return Schema::hasTable(self::TABLE);
        } catch (\Throwable) {
            return false;
        }
    }
}
