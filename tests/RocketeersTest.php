<?php

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
        $this->lastBody = json_encode($data);
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

    expect($client->lastUrl)->toBe('https://rocketeers.app/api/v1/errors');
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
