<?php

namespace Tuijncode\LaravelWaf\Services;

use Tuijncode\LaravelWaf\Rules\SignatureMatch;

/**
 * The outcome of inspecting a single request against the rule set.
 */
class InspectionResult
{
    /**
     * @param  array<int, SignatureMatch>  $matches
     * @param  array{score:int, label:string, anomaly_score:int}  $confidence
     */
    public function __construct(
        public readonly array $matches = [],
        public readonly bool $isScanner = false,
        public readonly ?string $scannerName = null,
        public readonly bool $isBot = false,
        public readonly ?string $botName = null,
        public readonly bool $isDdos = false,
        public readonly array $confidence = ['score' => 0, 'label' => 'none', 'anomaly_score' => 0],
    ) {}

    /**
     * Whether anything at all was flagged during inspection.
     */
    public function isThreat(): bool
    {
        return ! empty($this->matches) || $this->isScanner || $this->isBot || $this->isDdos;
    }

    public function anomalyScore(): int
    {
        return $this->confidence['anomaly_score'] ?? 0;
    }

    public function confidenceScore(): int
    {
        return $this->confidence['score'] ?? 0;
    }

    public function confidenceLabel(): string
    {
        return $this->confidence['label'] ?? 'none';
    }

    /**
     * A concise, human readable description of the strongest finding, used
     * as the `type` column in the log and in the dispatched event.
     */
    public function summary(): string
    {
        if (! empty($this->matches)) {
            $rule = $this->matches[0];

            return "[{$rule->id}] {$rule->description}";
        }

        if ($this->isScanner) {
            return "[913100] Scanner detected: {$this->scannerName}";
        }

        if ($this->isDdos) {
            return '[912100] Rate threshold exceeded (possible DoS)';
        }

        if ($this->isBot) {
            return "[913110] Automated client detected: {$this->botName}";
        }

        return 'No threat';
    }

    /**
     * The overall severity, taken from the most severe matched rule (or the
     * scanner/ddos signal), used for the `threat_level` column.
     */
    public function severity(): string
    {
        $order = ['critical' => 4, 'error' => 3, 'warning' => 2, 'notice' => 1];
        $highest = 0;
        $label = 'notice';

        foreach ($this->matches as $match) {
            $rank = $order[$match->severity] ?? 0;
            if ($rank > $highest) {
                $highest = $rank;
                $label = $match->severity;
            }
        }

        if ($this->isScanner || $this->isDdos) {
            return 'critical';
        }

        return $this->isThreat() ? $label : 'notice';
    }

    /**
     * The list of distinct rule ids that fired.
     *
     * @return array<int, string>
     */
    public function ruleIds(): array
    {
        return array_values(array_unique(array_map(fn (SignatureMatch $m) => $m->id, $this->matches)));
    }
}
