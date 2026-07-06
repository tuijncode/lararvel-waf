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
]);

it('assigns a severity to every scanner it knows', function () {
    expect($this->detector->detect('sqlmap')->severity)->toBeIn(['critical', 'error', 'warning', 'notice']);
});

it('ignores ordinary browser agents', function () {
    expect($this->detector->detect('Mozilla/5.0 (Windows NT 10.0; Win64; x64)'))->toBeNull()
        ->and($this->detector->isScanner('Mozilla/5.0'))->toBeFalse();
});
