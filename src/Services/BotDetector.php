<?php

namespace Tuijncode\LaravelWaf\Services;

/**
 * Bot / automated client detection.
 *
 * Flags suspicious User-Agents: scripting libraries, headless browsers and
 * empty/spoofed agents that legitimate browsers never send.
 */
class BotDetector
{
    /**
     * Suspicious automated-client fingerprints keyed by User-Agent needle.
     *
     * @var array<string, array{name:string, severity:string}>
     */
    protected array $bots = [
        'python-requests' => ['name' => 'Python Requests', 'severity' => 'warning'],
        'python-urllib' => ['name' => 'Python urllib', 'severity' => 'warning'],
        'go-http-client' => ['name' => 'Go HTTP Client', 'severity' => 'warning'],
        'java/' => ['name' => 'Java HTTP Client', 'severity' => 'warning'],
        'okhttp' => ['name' => 'OkHttp Client', 'severity' => 'notice'],
        'libwww-perl' => ['name' => 'libwww-perl', 'severity' => 'warning'],
        'curl/' => ['name' => 'cURL', 'severity' => 'notice'],
        'wget/' => ['name' => 'Wget', 'severity' => 'notice'],
        'httpclient' => ['name' => 'Generic HTTP Client', 'severity' => 'notice'],
        'headlesschrome' => ['name' => 'Headless Chrome', 'severity' => 'warning'],
        'phantomjs' => ['name' => 'PhantomJS', 'severity' => 'warning'],
        'puppeteer' => ['name' => 'Puppeteer', 'severity' => 'warning'],
        'playwright' => ['name' => 'Playwright', 'severity' => 'warning'],
        'selenium' => ['name' => 'Selenium', 'severity' => 'warning'],
        'scrapy' => ['name' => 'Scrapy', 'severity' => 'warning'],
    ];

    /**
     * Inspect a User-Agent for bot fingerprints.
     */
    public function detect(string $userAgent): ?Detection
    {
        $trimmed = trim($userAgent);

        if ($trimmed === '' || $trimmed === '-' || $trimmed === 'N/A') {
            return new Detection('Empty User-Agent', 'notice');
        }

        $ua = strtolower($trimmed);

        foreach ($this->bots as $needle => $info) {
            if (str_contains($ua, $needle)) {
                return new Detection($info['name'], $info['severity']);
            }
        }

        return null;
    }

    public function isBot(string $userAgent): bool
    {
        return $this->detect($userAgent) !== null;
    }
}
