<?php

use Rocketeers\Redactor;
use Rocketeers\Rocketeers;

class TestableRocketeers extends Rocketeers
{
    public string $lastUrl = '';
    public string $lastBody = '';
    public array $lastHeaders = [];
    public string $fakeResponse = '{"status":"ok"}';

    public function report(array $data)
    {
        if (isset($_SERVER['HTTP_HOST'])) {
            $referrer = 'http'.(isset($_SERVER['HTTPS']) ? 's' : '').'://'."{$_SERVER['HTTP_HOST']}/{$_SERVER['REQUEST_URI']}";
        }

        $this->lastUrl = $this->baseUrl . '/errors';
        $this->lastBody = json_encode($this->redactor()->redactPayload($data));
        $this->lastHeaders = [
            'Content-Type: application/json',
            'Accept: application/json',
            'Authorization: Bearer ' . $this->token,
            'Referer: ' . ($referrer ?? ''),
        ];

        return $this->fakeResponse;
    }
}

it('sends a report to the errors endpoint', function () {
    $client = new TestableRocketeers('test-token-123');
    $response = $client->report(['message' => 'Something went wrong']);

    expect($client->lastUrl)->toBe('https://api.rocketeersapp.com/v1/errors');
    expect($response)->toBe('{"status":"ok"}');
});

it('sends the correct authorization header', function () {
    $client = new TestableRocketeers('my-secret-token');
    $client->report(['error' => 'test']);

    expect($client->lastHeaders)->toContain('Authorization: Bearer my-secret-token');
});

it('sends json content type headers', function () {
    $client = new TestableRocketeers('token');
    $client->report(['error' => 'test']);

    expect($client->lastHeaders)->toContain('Content-Type: application/json');
    expect($client->lastHeaders)->toContain('Accept: application/json');
});

it('encodes report data as json', function () {
    $client = new TestableRocketeers('token');

    $data = [
        'message' => 'Error occurred',
        'level' => 'error',
        'context' => ['user_id' => 42],
    ];

    $client->report($data);

    expect(json_decode($client->lastBody, true))->toBe($data);
});

it('sends the referrer header from server variables', function () {
    $_SERVER['HTTP_HOST'] = 'example.com';
    $_SERVER['REQUEST_URI'] = '/some/page';
    unset($_SERVER['HTTPS']);

    $client = new TestableRocketeers('token');
    $client->report(['error' => 'test']);

    expect($client->lastHeaders)->toContain('Referer: http://example.com//some/page');

    unset($_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI']);
});

it('sends https referrer when HTTPS is set', function () {
    $_SERVER['HTTP_HOST'] = 'example.com';
    $_SERVER['REQUEST_URI'] = '/page';
    $_SERVER['HTTPS'] = 'on';

    $client = new TestableRocketeers('token');
    $client->report(['error' => 'test']);

    expect($client->lastHeaders)->toContain('Referer: https://example.com//page');

    unset($_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'], $_SERVER['HTTPS']);
});

it('sends an empty referrer when no server variables are set', function () {
    unset($_SERVER['HTTP_HOST']);

    $client = new TestableRocketeers('token');
    $client->report(['error' => 'test']);

    expect($client->lastHeaders)->toContain('Referer: ');
});

it('can be instantiated with a token', function () {
    $client = new Rocketeers('my-token');

    expect($client)->toBeInstanceOf(Rocketeers::class);
});

it('uses the default base url when no override is set', function () {
    Rocketeers::setBaseUrl('https://api.rocketeersapp.com/v1');

    $client = new TestableRocketeers('token');
    $client->report(['error' => 'test']);

    expect($client->lastUrl)->toBe('https://api.rocketeersapp.com/v1/errors');
});

it('uses the static base url override when set', function () {
    Rocketeers::setBaseUrl('https://custom.example.com/api/v1');

    $client = new TestableRocketeers('token');
    $client->report(['error' => 'test']);

    expect($client->lastUrl)->toBe('https://custom.example.com/api/v1/errors');

    // Reset for other tests
    Rocketeers::setBaseUrl('https://api.rocketeersapp.com/v1');
});

it('redacts the payload before it goes over the wire', function () {
    $client = new TestableRocketeers('token');

    $client->report([
        'code' => 500,
        'message' => 'boom',
        'inputs' => ['email' => 'mark@ux.nl', 'current_password' => 'hunter2'],
        'context' => ['credentials' => ['secret' => 'super-secret-value']],
    ]);

    $body = json_decode($client->lastBody, true);

    expect($client->lastBody)->not->toContain('hunter2')
        ->not->toContain('super-secret-value')
        ->and($body['code'])->toBe(500)
        ->and($body['inputs']['email'])->toBe('mark@ux.nl');
});

it('takes extra sensitive keys from the consumer', function () {
    $client = (new TestableRocketeers('token'))->setRedactor(new Redactor(['pincode']));

    $client->report(['inputs' => ['pincode' => '1234']]);

    expect($client->lastBody)->not->toContain('1234');
});

it('exposes the current base url', function () {
    expect(Rocketeers::baseUrl())->toBe('https://api.rocketeersapp.com/v1');

    Rocketeers::setBaseUrl('https://custom.example.com/api/v1');

    expect(Rocketeers::baseUrl())->toBe('https://custom.example.com/api/v1');

    Rocketeers::setBaseUrl('https://api.rocketeersapp.com/v1');
});

it('encodes a report exactly as report() always has, redacted', function () {
    $data = [
        'message' => "Invalid \xB1 byte",
        'inputs' => ['email' => 'mark@ux.nl', 'current_password' => 'hunter2'],
        'url' => 'https://app.test/callback?code=4ab19c',
        'trace' => [['file' => 'app/Foo.php', 'line' => 3, 'code_snippet' => [3 => '$x = 1;']]],
    ];

    $json = (new Rocketeers('token'))->encodeReport($data);

    expect($json)->toBe(json_encode((new Redactor)->redactPayload($data), JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR))
        ->not->toContain('hunter2')
        ->not->toContain('4ab19c');
});

it('posts what encodeReport() produced', function () {
    $client = new class('token') extends Rocketeers
    {
        public $posted = [];

        public function postReport($json)
        {
            $this->posted[] = $json;

            return '"OK"';
        }
    };

    $data = ['message' => 'boom', 'inputs' => ['secret' => 'shhh']];

    expect($client->report($data))->toBe('"OK"')
        ->and($client->posted)->toBe([$client->encodeReport($data)]);
});

it('posts the encoded report to the errors endpoint with the same headers as before', function () {
    if (! function_exists('proc_open')) {
        $this->markTestSkipped('proc_open is not available.');
    }

    $capture = tempnam(sys_get_temp_dir(), 'rocketeers-capture');
    $probe = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) substr(strrchr(stream_socket_get_name($probe, false), ':'), 1);
    fclose($probe);

    $server = proc_open(
        [PHP_BINARY, '-S', '127.0.0.1:'.$port, __DIR__.'/Fixtures/capture.php'],
        [['pipe', 'r'], ['file', '/dev/null', 'w'], ['pipe', 'w']],
        $pipes,
        null,
        ['ROCKETEERS_CAPTURE_FILE' => $capture] + getenv()
    );

    try {
        $deadline = microtime(true) + 5;
        $output = '';

        stream_set_blocking($pipes[2], false);

        while (strpos($output, 'started') === false && microtime(true) < $deadline) {
            $output .= (string) fread($pipes[2], 8192);
            usleep(20000);
        }

        $_SERVER['HTTP_HOST'] = 'example.com';
        $_SERVER['REQUEST_URI'] = '/page';
        unset($_SERVER['HTTPS']);

        Rocketeers::setBaseUrl('http://127.0.0.1:'.$port.'/v1');

        $client = new Rocketeers('my-token');
        $response = $client->postReport($json = $client->encodeReport(['message' => 'boom', 'inputs' => ['password' => 'hunter2']]));
        $request = json_decode(file_get_contents($capture), true);

        expect($response)->toBe('"OK"')
            ->and($request['method'])->toBe('POST')
            ->and($request['uri'])->toBe('/v1/errors')
            ->and($request['body'])->toBe($json)
            ->and($request['headers']['Content-Type'])->toBe('application/json')
            ->and($request['headers']['Accept'])->toBe('application/json')
            ->and($request['headers']['Authorization'])->toBe('Bearer my-token')
            ->and($request['headers']['Referer'])->toBe('http://example.com//page');
    } finally {
        unset($_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI']);
        Rocketeers::setBaseUrl('https://api.rocketeersapp.com/v1');
        proc_terminate($server);
        proc_close($server);
        @unlink($capture);
    }
});
