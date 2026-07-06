<?php

use Tuijncode\LaravelWaf\Services\BotDetector;

beforeEach(fn () => $this->detector = new BotDetector);

it('flags scripted clients and headless browsers', function (string $ua) {
    expect($this->detector->isBot($ua))->toBeTrue();
})->with([
    'python-requests/2.31.0',
    'Go-http-client/1.1',
    'curl/8.4.0',
    'HeadlessChrome/120.0.0.0',
    'Scrapy/2.11 (+https://scrapy.org)',
]);

it('treats an empty or dash user-agent as a bot', function (string $ua) {
    expect($this->detector->detect($ua))
        ->not->toBeNull()
        ->and($this->detector->detect($ua)->name)->toBe('Empty User-Agent');
})->with(['', '   ', '-', 'N/A']);

it('leaves a real browser alone', function () {
    $ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36';

    expect($this->detector->detect($ua))->toBeNull()
        ->and($this->detector->isBot($ua))->toBeFalse();
});
