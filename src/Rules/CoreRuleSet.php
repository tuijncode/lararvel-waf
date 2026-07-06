<?php

namespace Tuijncode\LaravelWaf\Rules;

/**
 * OWASP Core Rule Set (CRS) inspired signature collection.
 *
 * Each rule mirrors the structure of a real CRS rule: a stable rule id, the
 * CRS rule category (paranoia group), a human readable message, a severity
 * (which drives the anomaly score) and the request parts the rule targets.
 *
 * Severity to anomaly score mapping (as used by CRS):
 *   critical => 5, error => 4, warning => 3, notice => 2
 */
class CoreRuleSet
{
    public const SEVERITY_SCORES = [
        'critical' => 5,
        'error' => 4,
        'warning' => 3,
        'notice' => 2,
    ];

    /**
     * Rules that trade a little precision for breadth. They only run at
     * paranoia level 2 and above; at level 1 only the highest-confidence
     * signatures fire, which keeps false positives to a minimum.
     */
    public const BROAD_RULE_IDS = [
        '942110', // SELECT ... FROM
        '942120', // boolean tautology
        '942170', // SQL comment sequence
        '941120', // inline event handler
        '941130', // dangerous HTML tag
        '941140', // DOM sink
        '941150', // JS execution primitive
        '930100', // ../ traversal
        '931100', // RFI parameter
        '932100', // command chaining
        '932120', // unix binary
        '934110', // loopback SSRF
        '934120', // private-network SSRF
    ];

    /**
     * The paranoia level at which a rule id begins to fire (1 = always on).
     */
    public static function paranoiaFor(string $id): int
    {
        return in_array($id, self::BROAD_RULE_IDS, true) ? 2 : 1;
    }

    /**
     * The full signature list as typed value objects.
     *
     * @return array<int, Signature>
     */
    public static function rules(): array
    {
        return array_map(
            fn (array $r): Signature => new Signature(
                id: $r['id'],
                category: $r['category'],
                name: $r['name'],
                description: $r['description'],
                severity: $r['severity'],
                targets: $r['targets'],
                regex: $r['regex'],
                paranoia: self::paranoiaFor($r['id']),
            ),
            self::definitions(),
        );
    }

    /**
     * The raw rule definitions.
     *
     * @return array<int, array{id:string, category:string, name:string, description:string, severity:string, targets:array<int,string>, regex:string}>
     */
    private static function definitions(): array
    {
        return array_merge(
            self::sqlInjection(),
            self::crossSiteScripting(),
            self::localFileInclusion(),
            self::remoteFileInclusion(),
            self::remoteCommandExecution(),
            self::phpInjection(),
            self::serverSideRequestForgery(),
            self::xmlExternalEntity(),
            self::javaAndLog4Shell(),
            self::noSqlInjection(),
        );
    }

    /** REQUEST-942: SQL Injection Attacks. */
    protected static function sqlInjection(): array
    {
        return [
            [
                'id' => '942100',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: UNION SELECT detected',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path', 'headers', 'cookie'],
                'regex' => '/\bunion\b\s+(all\s+)?\bselect\b/i',
            ],
            [
                'id' => '942110',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: SELECT ... FROM detected',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path'],
                'regex' => '/\bselect\b[\s\S]{1,200}?\bfrom\b/i',
            ],
            [
                'id' => '942120',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: SQL boolean-based tautology (e.g. OR 1=1)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path', 'headers', 'cookie'],
                'regex' => '/\b(or|and)\b\s+["\']?\d+["\']?\s*(=|<>|!=|<|>)\s*["\']?\d+/i',
            ],
            [
                'id' => '942130',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: common DDL/DML keyword (drop/insert/update/delete)',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/\b(drop|alter|truncate|insert\s+into|delete\s+from|update)\b\s+[\w`\'"]+/i',
            ],
            [
                'id' => '942140',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: database metadata / schema probing',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/\b(information_schema|pg_catalog|sysobjects|mysql\.user|sqlite_master)\b/i',
            ],
            [
                'id' => '942150',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: time-based blind (sleep/benchmark/waitfor)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers', 'cookie'],
                'regex' => '/\b(sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b/i',
            ],
            [
                'id' => '942160',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: file read/write primitives (load_file/into outfile)',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/\b(load_file\s*\(|into\s+(out|dump)file)\b/i',
            ],
            [
                'id' => '942170',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: SQL comment sequence used for evasion',
                'severity' => 'error',
                'targets' => ['query', 'body', 'path'],
                'regex' => '/(--\s|#\s|\/\*!?)|;\s*(--|#)/',
            ],
        ];
    }

    /** REQUEST-941: Cross-Site Scripting (XSS). */
    protected static function crossSiteScripting(): array
    {
        return [
            [
                'id' => '941100',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: <script> tag detected',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path', 'headers'],
                'regex' => '/<script\b[^>]*>|<\/script\s*>/i',
            ],
            [
                'id' => '941110',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: javascript: URI scheme',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/javascript\s*:/i',
            ],
            [
                'id' => '941120',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: inline event handler (onerror/onload/onclick ...)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/\bon(error|load|click|mouseover|focus|submit|toggle|animationstart)\s*=/i',
            ],
            [
                'id' => '941130',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: dangerous HTML tag (iframe/object/embed/svg/img)',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/<(iframe|object|embed|svg|img|body|video|audio|marquee)\b[^>]*/i',
            ],
            [
                'id' => '941140',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: DOM access / JS sink (document.cookie, window.location)',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/document\s*\.\s*(cookie|location|write)|window\s*\.\s*location/i',
            ],
            [
                'id' => '941150',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: JS execution primitive (eval/alert/prompt/String.fromCharCode)',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/\b(eval|alert|confirm|prompt|atob|String\.fromCharCode)\s*\(/i',
            ],
            [
                'id' => '941160',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: URL-encoded <script> payload',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path'],
                'regex' => '/%3c\s*script|&lt;\s*script/i',
            ],
        ];
    }

    /** REQUEST-930: Local File Inclusion / Directory Traversal. */
    protected static function localFileInclusion(): array
    {
        return [
            [
                'id' => '930100',
                'category' => 'lfi',
                'name' => 'Directory Traversal',
                'description' => 'Path Traversal Attack: ../ or ..\\ sequence',
                'severity' => 'error',
                'targets' => ['query', 'body', 'path', 'headers'],
                'regex' => '/(\.\.[\/\\\\])|(%2e%2e[\/\\\\%])|(\.\.%2f)/i',
            ],
            [
                'id' => '930110',
                'category' => 'lfi',
                'name' => 'Directory Traversal',
                'description' => 'Path Traversal Attack: access to a well-known sensitive OS file',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path'],
                'regex' => '/(\/etc\/(passwd|shadow|hosts))|(\/proc\/self\/(environ|cmdline))|(boot\.ini)|(win\.ini)/i',
            ],
            [
                'id' => '930120',
                'category' => 'lfi',
                'name' => 'Local File Inclusion',
                'description' => 'LFI Attack: PHP stream wrapper (php://, file://, phar://, expect://)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path'],
                'regex' => '/\b(php|file|phar|expect|zip|glob|data):\/\//i',
            ],
        ];
    }

    /** REQUEST-931: Remote File Inclusion. */
    protected static function remoteFileInclusion(): array
    {
        return [
            [
                'id' => '931100',
                'category' => 'rfi',
                'name' => 'Remote File Inclusion',
                'description' => 'RFI Attack: remote URL passed to an inclusion parameter',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/[?&](file|path|page|include|template|document|folder|root|dir)=\s*(https?|ftp):\/\//i',
            ],
        ];
    }

    /** REQUEST-932: Remote Command Execution. */
    protected static function remoteCommandExecution(): array
    {
        return [
            [
                'id' => '932100',
                'category' => 'rce',
                'name' => 'RCE',
                'description' => 'RCE Attack: shell command chaining / substitution',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                // A separator (; | & newline backtick) immediately followed by a
                // shell command, or a command-substitution construct. Requiring a
                // trailing command avoids matching the many legitimate semicolons
                // that appear in headers, cookies and query strings.
                'regex' => '/(\$\(|`|\|\s*)\s*(cat|ls|id|whoami|nc|netcat|curl|wget|bash|sh|python|perl|ping|uname|chmod|rm|echo|kill|dir|type)\b|[;&|]{1,2}\s*(cat|ls|id|whoami|nc|curl|wget|bash|sh|ping|uname|chmod|rm|echo)\b|\bIFS\b/i',
            ],
            [
                'id' => '932110',
                'category' => 'rce',
                'name' => 'RCE',
                'description' => 'RCE Attack: PHP/system command execution function',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/\b(system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(/i',
            ],
            [
                'id' => '932120',
                'category' => 'rce',
                'name' => 'RCE',
                'description' => 'RCE Attack: common unix binary invoked as a command',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/\b(cat|nc|netcat|ncat|ping|wget|curl|whoami|id|uname|ls|dir|chmod|chown|kill|nslookup|dig)\b\s+[-\/\w]/i',
            ],
            [
                'id' => '932130',
                'category' => 'rce',
                'name' => 'RCE',
                'description' => 'RCE Attack: reverse shell / bind shell primitive',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/(\/bin\/(ba|z|c|k)?sh)|(\/dev\/tcp\/)|(bash\s+-i)/i',
            ],
        ];
    }

    /** REQUEST-933: PHP Injection. */
    protected static function phpInjection(): array
    {
        return [
            [
                'id' => '933100',
                'category' => 'php',
                'name' => 'PHP Injection',
                'description' => 'PHP Injection Attack: opening PHP tag',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/<\?(php|=)?\s/i',
            ],
            [
                'id' => '933110',
                'category' => 'php',
                'name' => 'PHP Injection',
                'description' => 'PHP Injection Attack: dangerous PHP function (eval/assert/base64_decode/create_function)',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/\b(eval|assert|create_function|base64_decode|gzinflate|str_rot13|call_user_func(_array)?)\s*\(/i',
            ],
            [
                'id' => '933120',
                'category' => 'php',
                'name' => 'PHP Injection',
                'description' => 'PHP Injection Attack: PHP superglobal reference',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/\$_(GET|POST|REQUEST|SERVER|COOKIE|SESSION|ENV|FILES)\b/i',
            ],
            [
                'id' => '933130',
                'category' => 'php',
                'name' => 'PHP Object Injection',
                'description' => 'PHP Injection Attack: serialized object (insecure deserialization)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'cookie'],
                'regex' => '/\bO:\d+:"[a-z_\x80-\xff][a-z0-9_\x80-\xff]*":\d+:{/i',
            ],
        ];
    }

    /** REQUEST-934: Server-Side Request Forgery. */
    protected static function serverSideRequestForgery(): array
    {
        return [
            [
                'id' => '934100',
                'category' => 'ssrf',
                'name' => 'SSRF',
                'description' => 'SSRF Attack: cloud metadata endpoint (169.254.169.254 / metadata.google.internal)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/(169\.254\.169\.254)|(metadata\.google\.internal)|(metadata\.azure\.com)/i',
            ],
            [
                'id' => '934110',
                'category' => 'ssrf',
                'name' => 'SSRF',
                'description' => 'SSRF Attack: request pointed at loopback / localhost',
                'severity' => 'error',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/(https?|gopher|dict|ftp):\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)/i',
            ],
            [
                'id' => '934120',
                'category' => 'ssrf',
                'name' => 'SSRF',
                'description' => 'SSRF Attack: request pointed at RFC1918 private network',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/(https?|gopher|dict|ftp):\/\/(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}/i',
            ],
        ];
    }

    /** XML External Entity. */
    protected static function xmlExternalEntity(): array
    {
        return [
            [
                'id' => '944100',
                'category' => 'xxe',
                'name' => 'XXE',
                'description' => 'XXE Attack: external entity declaration',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/<!ENTITY\b/i',
            ],
            [
                'id' => '944110',
                'category' => 'xxe',
                'name' => 'XXE',
                'description' => 'XXE Attack: DOCTYPE with entity/SYSTEM declaration',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/<!DOCTYPE[^>]*(ENTITY|SYSTEM)/is',
            ],
        ];
    }

    /** REQUEST-944: Java attacks including Log4Shell. */
    protected static function javaAndLog4Shell(): array
    {
        return [
            [
                'id' => '944150',
                'category' => 'log4shell',
                'name' => 'Log4Shell',
                'description' => 'Log4Shell Attack: JNDI lookup (${jndi:ldap://...})',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers', 'cookie'],
                'regex' => '/\$\{jndi:(ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http)s?:/i',
            ],
            [
                'id' => '944160',
                'category' => 'log4shell',
                'name' => 'Log4Shell',
                'description' => 'Log4Shell Attack: obfuscated JNDI lookup expression',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers', 'cookie'],
                'regex' => '/\$\{[^}]*(jndi|lower:|upper:|env:|sys:|::-)[^}]*\}/i',
            ],
        ];
    }

    /** REQUEST-934: NoSQL Injection (Node / Mongo). */
    protected static function noSqlInjection(): array
    {
        return [
            [
                'id' => '934200',
                'category' => 'nosqli',
                'name' => 'NoSQL Injection',
                'description' => 'NoSQL Injection Attack: Mongo operator ($ne/$gt/$where/$regex/$in)',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/[\[{"\']?\s*\$(ne|gt|gte|lt|lte|where|regex|in|nin|or|and|not|exists)\s*["\']?\s*[:=]/i',
            ],
        ];
    }
}
