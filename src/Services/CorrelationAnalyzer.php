<?php

namespace Tuijncode\LaravelWaf\Services;

use Illuminate\Support\Facades\DB;

/**
 * Reads the `waf_logs` table to surface attacks that only reveal themselves in
 * aggregate: the same target hit from many IPs, a single attack class spreading
 * across the fleet, or one IP hammering many endpoints at once.
 */
class CorrelationAnalyzer
{
    private function table(): string
    {
        return config('waf.table_name', 'waf_logs');
    }

    /**
     * URLs targeted by several distinct IPs inside a short window — the classic
     * signature of a distributed / coordinated attack.
     *
     * @return array<int, array{url:string, ips:int, hits:int, first_seen:?string, last_seen:?string}>
     */
    public function coordinatedAttacks(int $windowMinutes = 15, int $minIps = 3, int $limit = 20): array
    {
        return DB::table($this->table())
            ->where('created_at', '>=', now()->subMinutes($windowMinutes))
            ->select(
                'url',
                DB::raw('COUNT(DISTINCT ip_address) as ips'),
                DB::raw('COUNT(*) as hits'),
                DB::raw('MIN(created_at) as first_seen'),
                DB::raw('MAX(created_at) as last_seen'),
            )
            ->groupBy('url')
            ->havingRaw('COUNT(DISTINCT ip_address) >= ?', [$minIps])
            ->orderByDesc('ips')
            ->limit($limit)
            ->get()
            ->map(fn ($row): array => (array) $row)
            ->all();
    }

    /**
     * Attack classes (categories) mounted by many distinct IPs over a longer
     * horizon — a campaign rather than a one-off probe.
     *
     * @return array<int, array{category:string, ips:int, hits:int, first_seen:?string, last_seen:?string}>
     */
    public function campaigns(int $windowHours = 24, int $minIps = 5, int $limit = 20): array
    {
        return DB::table($this->table())
            ->where('created_at', '>=', now()->subHours($windowHours))
            ->select(
                'category',
                DB::raw('COUNT(DISTINCT ip_address) as ips'),
                DB::raw('COUNT(*) as hits'),
                DB::raw('MIN(created_at) as first_seen'),
                DB::raw('MAX(created_at) as last_seen'),
            )
            ->groupBy('category')
            ->havingRaw('COUNT(DISTINCT ip_address) >= ?', [$minIps])
            ->orderByDesc('ips')
            ->limit($limit)
            ->get()
            ->map(fn ($row): array => (array) $row)
            ->all();
    }

    /**
     * Single IPs generating a burst of findings across (potentially) many
     * distinct attack types in a short window.
     *
     * @return array<int, array{ip_address:string, hits:int, types:int, first_seen:?string, last_seen:?string}>
     */
    public function rapidAttackers(int $windowMinutes = 5, int $minHits = 10, int $limit = 20): array
    {
        return DB::table($this->table())
            ->where('created_at', '>=', now()->subMinutes($windowMinutes))
            ->select(
                'ip_address',
                DB::raw('COUNT(*) as hits'),
                DB::raw('COUNT(DISTINCT type) as types'),
                DB::raw('MIN(created_at) as first_seen'),
                DB::raw('MAX(created_at) as last_seen'),
            )
            ->groupBy('ip_address')
            ->havingRaw('COUNT(*) >= ?', [$minHits])
            ->orderByDesc('hits')
            ->limit($limit)
            ->get()
            ->map(fn ($row): array => (array) $row)
            ->all();
    }

    /**
     * A one-line count of each correlation signal, for dashboards / cron.
     *
     * @return array{coordinated_attacks:int, campaigns:int, rapid_attackers:int}
     */
    public function summary(): array
    {
        return [
            'coordinated_attacks' => count($this->coordinatedAttacks()),
            'campaigns' => count($this->campaigns()),
            'rapid_attackers' => count($this->rapidAttackers()),
        ];
    }
}
