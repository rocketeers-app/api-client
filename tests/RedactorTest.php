<?php

use Rocketeers\Redactor;

it('masks a credential whatever the exact key is called', function () {
    $redacted = (new Redactor)->redactArray([
        'current_password' => 'hunter2',
        'client_secret' => 'sk_live_abc',
        'refresh_token' => 'rt_abc',
        'X-Api-Key' => 'k_abc',
        'credentials' => ['key' => 'AKIAEXAMPLE', 'secret' => 'shhh'],
        'user' => ['id' => 7, 'sudo_password' => 'root123'],
    ]);

    expect($redacted)->toBe([
        'current_password' => Redactor::REDACTED,
        'client_secret' => Redactor::REDACTED,
        'refresh_token' => Redactor::REDACTED,
        'X-Api-Key' => Redactor::REDACTED,
        'credentials' => Redactor::REDACTED,
        'user' => ['id' => 7, 'sudo_password' => Redactor::REDACTED],
    ]);
});

it('leaves ordinary data untouched', function () {
    $context = ['server_id' => 4, 'region' => 'ams3', 'bucket' => 'backups', 'attempt' => 2];

    expect((new Redactor)->redactArray($context))->toBe($context);
});

it('accepts extra key fragments from the consumer', function () {
    $redacted = (new Redactor(['pincode']))->redactArray(['pincode' => '1234', 'name' => 'Mark']);

    expect($redacted)->toBe(['pincode' => Redactor::REDACTED, 'name' => 'Mark']);
});

it('scrubs a private key', function () {
    $key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----";

    expect((new Redactor)->redactString("writing {$key} failed"))
        ->not->toContain('b3BlbnNzaC1rZXktdjEAAAAA')
        ->toContain(Redactor::REDACTED);
});

it('scrubs a bearer token', function () {
    expect((new Redactor)->redactString('curl -H "Authorization: Bearer 12|aBcDeFgHiJkLmNoP"'))
        ->not->toContain('aBcDeFgHiJkLmNoP');
});

it('scrubs a database password from a shell command', function () {
    expect((new Redactor)->redactString("sudo env MYSQL_PWD='s3cr3tvalue' mysql -u root"))
        ->not->toContain('s3cr3tvalue');
});

it('scrubs the signature out of a signed url', function () {
    $url = 'https://app.test/backups/9/download?expires=1700000000&signature=8f14e45fceea167a';

    expect((new Redactor)->redactString($url))
        ->toBe('https://app.test/backups/9/download?expires=1700000000&signature='.Redactor::REDACTED);
});

/**
 * A queued job's raw body is JSON, so the credential inside is named by a key rather than
 * shaped like one — decoding is the only way to reach it.
 */
it('walks into a json string rather than matching it as one blob', function () {
    $body = json_encode([
        'displayName' => 'App\Jobs\SyncStorages',
        'data' => ['credentials' => ['secret' => 'super-secret-value']],
    ]);

    $redacted = (new Redactor)->redactString($body);

    expect($redacted)->not->toContain('super-secret-value')
        ->and(json_decode($redacted, true)['displayName'])->toBe('App\Jobs\SyncStorages');
});

it('leaves a string that only looks like json alone', function () {
    expect((new Redactor)->redactString('{not really json'))->toBe('{not really json');
});

/**
 * `code` is the HTTP status of the report and `cookies` the whole cookie jar; matching the
 * report's own field names would blank out the report itself.
 */
it('never matches the reports own field names', function () {
    $payload = (new Redactor)->redactPayload([
        'code' => 500,
        'message' => 'boom',
        'sessions' => ['url' => ['intended' => 'https://app.test/servers']],
        'cookies' => ['XSRF-TOKEN' => 'abc', 'remember_me' => 'plain'],
    ]);

    expect($payload['code'])->toBe(500)
        ->and($payload['message'])->toBe('boom')
        ->and($payload['sessions']['url']['intended'])->toBe('https://app.test/servers')
        ->and($payload['cookies']['XSRF-TOKEN'])->toBe(Redactor::REDACTED)
        ->and($payload['cookies']['remember_me'])->toBe('plain');
});

/**
 * An OAuth `code` is a credential in a query string; an exit `code` in log context is not.
 */
it('treats code as a credential only in request data', function () {
    $payload = (new Redactor)->redactPayload([
        'querystring' => ['code' => '4ab19c', 'team' => '3'],
        'context' => ['code' => 255, 'command' => 'nginx -t'],
    ]);

    expect($payload['querystring'])->toBe(['code' => Redactor::REDACTED, 'team' => '3'])
        ->and($payload['context'])->toBe(['code' => 255, 'command' => 'nginx -t']);
});

it('scrubs a credential out of the reported url', function () {
    $payload = (new Redactor)->redactPayload([
        'url' => 'https://app.test/auth/github/callback?code=4ab19c&team=3',
    ]);

    expect($payload['url'])->toBe('https://app.test/auth/github/callback?code='.Redactor::REDACTED.'&team=3');
});

it('keeps the indentation and brackets of a line of code', function () {
    $redactor = new Redactor;

    expect($redactor->redactCode('        $items = [];'))->toBe('        $items = [];')
        ->and($redactor->redactCode('    []'))->toBe('    []')
        ->and($redactor->redactCode('    {'))->toBe('    {')
        ->and($redactor->redactCode('    public function send(&$apiKey = null, $url = "?token=1")'))
        ->toBe('    public function send(&$apiKey = null, $url = "?token=1")');
});

it('scrubs a bearer token and a private key out of a line of code', function () {
    $redactor = new Redactor;

    expect($redactor->redactCode("        ->withHeaders(['Authorization: Bearer 12|aBcDeFgHiJkLmNoP'])"))
        ->toBe("        ->withHeaders(['Authorization: Bearer ".Redactor::REDACTED."'])")
        ->and($redactor->redactCode('    $key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";'))
        ->toBe('    $key = "'.Redactor::REDACTED.'";');
});

it('scrubs a private key spread over the lines of a snippet', function () {
    $snippet = (new Redactor)->redactCodeSnippet([
        10 => '    $key = <<<KEY',
        11 => '    -----BEGIN OPENSSH PRIVATE KEY-----',
        12 => '    b3BlbnNzaC1rZXktdjEAAAAA',
        13 => '    -----END OPENSSH PRIVATE KEY-----',
        14 => '    KEY;',
    ]);

    expect($snippet)->toBe([
        10 => '    $key = <<<KEY',
        11 => '    '.Redactor::REDACTED,
        12 => '    '.Redactor::REDACTED,
        13 => '    '.Redactor::REDACTED,
        14 => '    KEY;',
    ]);
});

it('scrubs a private key the snippet starts or ends inside of', function () {
    $redactor = new Redactor;

    expect($redactor->redactCodeSnippet([
        1 => 'b3BlbnNzaC1rZXktdjEAAAAA',
        2 => '-----END OPENSSH PRIVATE KEY-----";',
        3 => 'return $key;',
    ]))->toBe([1 => Redactor::REDACTED, 2 => Redactor::REDACTED.'";', 3 => 'return $key;'])
        ->and($redactor->redactCodeSnippet([
            7 => '$key = "-----BEGIN OPENSSH PRIVATE KEY-----',
            8 => 'b3BlbnNzaC1rZXktdjEAAAAA',
        ]))->toBe([7 => '$key = "'.Redactor::REDACTED, 8 => Redactor::REDACTED]);
});

it('redacts the code of a reported frame as code and the rest of it as data', function () {
    $payload = (new Redactor)->redactPayload([
        'trace' => [
            [
                'file' => 'app/Services/Genesys.php',
                'line' => 31,
                'function' => 'send',
                'code_snippet' => [
                    30 => '        $headers = [];',
                    31 => "        \$this->post('https://genesys.test?token=abc', ['Authorization: Bearer 12|aBcDeFgHiJkLmNoP']);",
                ],
            ],
            ['file' => 'https://app.test/callback?code=4ab19c', 'line' => 3],
        ],
    ]);

    expect($payload['trace'][0]['code_snippet'])->toBe([
        30 => '        $headers = [];',
        31 => "        \$this->post('https://genesys.test?token=abc', ['Authorization: Bearer ".Redactor::REDACTED."']);",
    ])
        ->and($payload['trace'][0]['function'])->toBe('send')
        ->and($payload['trace'][1]['file'])->toBe('https://app.test/callback?code='.Redactor::REDACTED);
});
