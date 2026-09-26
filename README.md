# Rocketeers API Client

[![Latest Version on Packagist](https://img.shields.io/packagist/v/rocketeers-app/rocketeers-api-client.svg?style=flat-square)](https://packagist.org/packages/rocketeers-app/rocketeers-api-client)
[![Total Downloads](https://img.shields.io/packagist/dt/rocketeers-app/rocketeers-api-client.svg?style=flat-square)](https://packagist.org/packages/rocketeers-app/rocketeers-api-client)

A lightweight PHP client for the [Rocketeers](https://rocketeers.app) API. Report errors from any PHP application.

## Requirements

- PHP 7.0+

## Installation

```bash
composer require rocketeers-app/rocketeers-api-client
```

## Usage

```php
use Rocketeers\Rocketeers;

$client = new Rocketeers('your-api-token');

$client->report([
    'message' => 'Something went wrong',
    'level' => 'error',
    'context' => ['user_id' => 42],
]);
```

## Redaction

Every report is scrubbed by `Rocketeers\Redactor` before it is sent, so a credential that ends up
in an exception message, a request payload or a queued job body never leaves the process.

Field names are matched as a **substring**, lower-cased with dashes normalised to underscores, so
one entry covers a family of names: `secret` also covers `client_secret`, `token` also covers
`refresh_token`, and `api_key` also covers `X-Api-Key`. Credentials with no field name to recognise
them by are matched by shape — private key blocks, `Authorization` headers, `MYSQL_PWD=`,
`--password=`, `sshpass -p`, SQL `IDENTIFIED BY`, and credential-shaped query parameters in a URL.
A string holding JSON is decoded and walked rather than matched as one blob.

The report's own field names are never matched, so `code` stays the HTTP status and `cookies` stays
the cookie jar; inside request fields (`querystring`, `inputs`, `headers`, `cookies`, `sessions`)
`code`, `key` and `state` are treated as credentials too.

Pass extra field names your application uses; the built-in list is never replaced:

```php
use Rocketeers\Redactor;
use Rocketeers\Rocketeers;

$client = (new Rocketeers('your-api-token'))->setRedactor(new Redactor(['pincode', 'bsn']));
```

## Testing

```bash
composer test
```

## Security

If you discover any security related issues, please email mark@vaneijk.co instead of using the issue tracker.

## Credits

- [Mark van Eijk](https://github.com/markvaneijk)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
