# Rocketeers API Client

[![Latest Version on Packagist](https://img.shields.io/packagist/v/rocketeers-app/rocketeers-api-client.svg?style=flat-square)](https://packagist.org/packages/rocketeers-app/rocketeers-api-client)
[![Total Downloads](https://img.shields.io/packagist/dt/rocketeers-app/rocketeers-api-client.svg?style=flat-square)](https://packagist.org/packages/rocketeers-app/rocketeers-api-client)

A lightweight PHP client for the [Rocketeers](https://rocketeers.app) API. Report errors from any PHP application.

## Requirements

- PHP 8.2+

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
