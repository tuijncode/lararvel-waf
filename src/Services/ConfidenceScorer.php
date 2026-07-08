<?php

namespace Tuijncode\LaravelWaf\Services;

use Tuijncode\LaravelWaf\Rules\SignatureMatch;

/**
 * Confidence scoring.
 *
 * Combines the OWASP CRS anomaly score (sum of matched-rule severities) with
 * contextual signals into a single, easy to reason about 0-100 confidence
 * value plus a categorical label.
 */
class ConfidenceScorer
{
    /**
     * @param  array<int, SignatureMatch>  $matches  matched rules
     * @param  bool  $isScanner  request came from a known security scanner
     * @param  bool  $isBot  request came from an automated client
     * @param  bool  $isDdos  request tripped the rate threshold
     * @return array{score:int, label:string, anomaly_score:int}
     */
    public function calculate(array $matches, bool $isScanner = false, bool $isBot = false, bool $isDdos = false): array
    {
        $anomalyScore = 0;
        foreach ($matches as $match) {
            $anomalyScore += $match->anomalyScore();
        }

        if (empty($matches) && ! $isScanner && ! $isBot && ! $isDdos) {
            return ['score' => 0, 'label' => 'none', 'anomaly_score' => 0];
        }

        $score = 0;

        // Anomaly score is the strongest signal: 8 points per severity point,
        // saturating quickly so a single critical rule (5) already scores 40.
        $score += min($anomalyScore * 8, 70);

        // Breadth: multiple distinct rule matches raise confidence.
        $distinct = count($matches);
        if ($distinct > 1) {
            $score += min(($distinct - 1) * 6, 18);
        }

        // Query/path matches are more suspicious than body content.
        foreach ($matches as $match) {
            if (in_array($match->context, ['query', 'path'], true)) {
                $score += 5;
                break;
            }
        }

        // Contextual signals.
        if ($isScanner) {
            $score += 30;
        }

        if ($isBot) {
            $score += 8;
        }

        if ($isDdos) {
            $score += 25;
        }

        // Decisive signatures (e.g. a bare `.env` or `.git/config` probe) have no
        // legitimate use, so a single hit is treated as a certainty: full score,
        // which guarantees a block in blocking mode regardless of block_confidence.
        foreach ($matches as $match) {
            if ($match->decisive) {
                $score = 100;
                break;
            }
        }

        $score = max(0, min(100, $score));

        return [
            'score' => $score,
            'label' => $this->label($score),
            'anomaly_score' => $anomalyScore,
        ];
    }

    public function label(int $score): string
    {
        return match (true) {
            $score >= 80 => 'critical',
            $score >= 60 => 'high',
            $score >= 35 => 'medium',
            $score > 0 => 'low',
            default => 'none',
        };
    }
}
