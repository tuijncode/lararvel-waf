<?php

use Tuijncode\LaravelWaf\Services\ScannerDetector;

beforeEach(fn () => $this->detector = new ScannerDetector);

it('identifies known scanners by user-agent', function (string $ua, string $name) {
    expect($this->detector->detect($ua))
        ->not->toBeNull()
        ->and($this->detector->detect($ua)->name)->toBe($name);

    expect($this->detector->isScanner($ua))->toBeTrue();
})->with([
    ['sqlmap/1.7#stable', 'SQLMap'],
    ['Mozilla/5.0 nikto', 'Nikto'],
    ['Nmap Scripting Engine', 'Nmap'],
    ['Nuclei - Open-source project', 'Nuclei'],
    ['() { :; }; curl acunetix', 'Acunetix'],
    ['Arachni/v1.6.1.3', 'Arachni'],
    ['Mozilla/5.0 (compatible; wapiti 3.1.0)', 'Wapiti'],
    ['commix/v3.7', 'Commix'],
    ['Fuzz Faster U Fool v2.1.0 ffuf', 'FFUF'],
    ['feroxbuster/2.10.1', 'FeroxBuster'],
    ['dalfox/2.9', 'Dalfox'],
    ['XSStrike/3.1.5', 'XSStrike'],
    ['skipfish version 2.10b', 'Skipfish'],
]);

it('assigns a severity to every scanner it knows', function () {
    expect($this->detector->detect('sqlmap')->severity)->toBeIn(['critical', 'error', 'warning', 'notice']);
});

it('ignores ordinary browser agents', function () {
    expect($this->detector->detect('Mozilla/5.0 (Windows NT 10.0; Win64; x64)'))->toBeNull()
        ->and($this->detector->isScanner('Mozilla/5.0'))->toBeFalse();
});

it('identifies OWASP ZAP by its full fingerprint', function (string $ua) {
    expect($this->detector->detect($ua)?->name)->toBe('OWASP ZAP');
})->with([
    'Mozilla/5.0 (compatible; OWASP ZAP/2.14)',
    'zaproxy/2.14.0',
]);

it('does not mistake Zapier for OWASP ZAP', function () {
    expect($this->detector->detect('Zapier/1.0 (+https://zapier.com/webhooks)'))->toBeNull();
});
