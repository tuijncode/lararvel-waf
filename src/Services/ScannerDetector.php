<?php

namespace Tuijncode\LaravelWaf\Services;

/**
 * REQUEST-913: Scanner / security tool detection.
 *
 * Identifies well-known vulnerability scanners and penetration testing tools
 * by their default User-Agent fingerprints.
 */
class ScannerDetector
{
    /**
     * Known security scanners keyed by their User-Agent fingerprint.
     *
     * @var array<string, array{name:string, severity:string}>
     */
    protected array $scanners = [
        'sqlmap' => ['name' => 'SQLMap', 'severity' => 'critical'],
        'nikto' => ['name' => 'Nikto', 'severity' => 'critical'],
        'nmap' => ['name' => 'Nmap', 'severity' => 'critical'],
        'masscan' => ['name' => 'Masscan', 'severity' => 'critical'],
        'acunetix' => ['name' => 'Acunetix', 'severity' => 'critical'],
        'wpscan' => ['name' => 'WPScan', 'severity' => 'error'],
        'nessus' => ['name' => 'Nessus', 'severity' => 'critical'],
        'openvas' => ['name' => 'OpenVAS', 'severity' => 'critical'],
        'nuclei' => ['name' => 'Nuclei', 'severity' => 'critical'],
        'burp' => ['name' => 'Burp Suite', 'severity' => 'error'],
        'zap' => ['name' => 'OWASP ZAP', 'severity' => 'error'],
        'metasploit' => ['name' => 'Metasploit', 'severity' => 'critical'],
        'w3af' => ['name' => 'w3af', 'severity' => 'critical'],
        'havij' => ['name' => 'Havij', 'severity' => 'critical'],
        'netsparker' => ['name' => 'Netsparker', 'severity' => 'critical'],
        'appscan' => ['name' => 'AppScan', 'severity' => 'critical'],
        'dirbuster' => ['name' => 'DirBuster', 'severity' => 'error'],
        'gobuster' => ['name' => 'Gobuster', 'severity' => 'error'],
        'zgrab' => ['name' => 'ZGrab', 'severity' => 'error'],
        'zmap' => ['name' => 'ZMap', 'severity' => 'error'],
        'shodan' => ['name' => 'Shodan', 'severity' => 'warning'],
        'censys' => ['name' => 'Censys', 'severity' => 'warning'],
    ];

    /**
     * Inspect a User-Agent for scanner fingerprints.
     */
    public function detect(string $userAgent): ?Detection
    {
        $ua = strtolower($userAgent);

        foreach ($this->scanners as $needle => $info) {
            if (str_contains($ua, $needle)) {
                return new Detection($info['name'], $info['severity']);
            }
        }

        return null;
    }

    public function isScanner(string $userAgent): bool
    {
        return $this->detect($userAgent) !== null;
    }
}
