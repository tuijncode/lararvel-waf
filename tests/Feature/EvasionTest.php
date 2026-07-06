<?php

use Illuminate\Support\Facades\DB;

it('sees through HTML-entity-encoded XSS', function () {
    $this->get('/?q='.rawurlencode('&lt;script&gt;alert(1)&lt;/script&gt;'))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('941100');
});

it('sees through double URL-encoding', function () {
    // %253Cscript%253E → %3Cscript%3E → <script>
    $this->get('/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('941100');
});

it('sees through null-byte splitting', function () {
    // /etc/pass\0wd — the null byte splits the signature until it is stripped.
    $this->get('/?file=/etc/pass%00wd')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('930110');
});
