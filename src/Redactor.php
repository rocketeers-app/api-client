<?php

namespace Rocketeers;

/**
 * Strips credentials out of a report before it leaves the process. Every path into the API —
 * the Monolog handler, the queued-job listener, anything a consumer builds by hand — goes
 * through Rocketeers::report(), so this is the one place that has to be right.
 */
class Redactor
{
    const REDACTED = '[redacted]';

    /**
     * Matched as a substring of the key, lower-cased with dashes normalised to underscores,
     * so `current_password`, `client_secret` and `X-Api-Key` are all covered by one entry.
     */
    const SENSITIVE_KEYS = [
        'password',
        'passwd',
        'secret',
        'token',
        'authorization',
        'credential',
        'api_key',
        'apikey',
        'access_key',
        'private_key',
        'ssh_key',
        'signature',
        'session',
        'cookie',
        'credit_card',
        'card_number',
        'cvv',
        'ssn',
    ];

    /**
     * Only applied to data taken off the request, where `code` is an OAuth authorization code
     * and `key` an API key. Elsewhere those names mean an HTTP status or an array key.
     */
    const SENSITIVE_REQUEST_KEYS = [
        'code',
        'key',
        'state',
    ];

    /** Report fields carrying request data, whose keys are matched against both lists. */
    const REQUEST_FIELDS = [
        'querystring',
        'inputs',
        'headers',
        'cookies',
        'sessions',
    ];

    /** Credential shapes that carry no key to recognise them by. */
    const SECRET_PATTERNS = [
        '/-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/s',
        '/(?<=Authorization: Bearer )([A-Za-z0-9|._\-]+)/i',
        '/(?<=Authorization: Basic )([A-Za-z0-9+\/=]+)/i',
        '/(?<=MYSQL_PWD=)(\'[^\']*\'|"[^"]*"|\S+)/',
        '/(?<=--password=)("[^"]*"|\'[^\']*\'|\S+)/',
        '/(?<=sshpass -p )(\'[^\']*\'|"[^"]*"|\S+)/',
        '/(?<=IDENTIFIED BY )(\'(?:[^\']|\'\')*\')/i',
    ];

    /** A credential named in a URL query string, wherever that URL turns up. */
    const QUERY_PATTERN = '/([?&][^=&\s#]*(?:password|passwd|secret|token|signature|api[_-]?key|credential|code|key)[^=&\s#]*=)[^&\s#]*/i';

    /** @var array */
    private $keys;

    /** @var array */
    private $requestKeys;

    /**
     * @param  array  $additionalKeys  Extra key fragments to treat as sensitive.
     */
    public function __construct(array $additionalKeys = [])
    {
        $this->keys = array_values(array_unique(array_merge(
            self::SENSITIVE_KEYS,
            array_map('strtolower', $additionalKeys)
        )));

        $this->requestKeys = array_merge($this->keys, self::SENSITIVE_REQUEST_KEYS);
    }

    /**
     * The report's own field names are never matched: `code` is the HTTP status and `cookies`
     * the whole cookie jar, so matching those would blank out the report itself.
     *
     * @return array
     */
    public function redactPayload(array $payload)
    {
        $redacted = [];

        foreach ($payload as $field => $value) {
            $redacted[$field] = is_array($value) && in_array($field, self::REQUEST_FIELDS, true)
                ? $this->redactRequestData($value)
                : $this->redact($value);
        }

        return $redacted;
    }

    /**
     * @return array
     */
    public function redactArray(array $data)
    {
        return $this->redactKeyed($data, $this->keys);
    }

    /**
     * @return array
     */
    public function redactRequestData(array $data)
    {
        return $this->redactKeyed($data, $this->requestKeys);
    }

    /**
     * @return mixed
     */
    public function redact($value)
    {
        if (is_array($value)) {
            return $this->redactArray($value);
        }

        return is_string($value) ? $this->redactString($value) : $value;
    }

    /**
     * A queued job's raw body and a logged response body are JSON, and the credential inside
     * is named by a key no pattern can see, so JSON is decoded and walked rather than matched
     * as one long string.
     *
     * @return string
     */
    public function redactString($value)
    {
        $decoded = $this->decodeJson($value);

        if ($decoded !== null) {
            $encoded = json_encode($this->redactArray($decoded));

            if ($encoded !== false) {
                return $encoded;
            }
        }

        foreach (self::SECRET_PATTERNS as $pattern) {
            $value = preg_replace($pattern, self::REDACTED, $value);
        }

        return preg_replace(self::QUERY_PATTERN, '$1'.self::REDACTED, $value);
    }

    /**
     * @return array|null
     */
    private function decodeJson($value)
    {
        $trimmed = ltrim($value);

        if ($trimmed === '' || ($trimmed[0] !== '{' && $trimmed[0] !== '[')) {
            return null;
        }

        $decoded = json_decode($value, true);

        return is_array($decoded) && json_last_error() === JSON_ERROR_NONE ? $decoded : null;
    }

    /**
     * @return array
     */
    private function redactKeyed(array $data, array $keys)
    {
        $redacted = [];

        foreach ($data as $key => $value) {
            if ($this->isSensitiveKey($key, $keys)) {
                $redacted[$key] = self::REDACTED;
            } elseif (is_array($value)) {
                $redacted[$key] = $this->redactKeyed($value, $keys);
            } else {
                $redacted[$key] = $this->redact($value);
            }
        }

        return $redacted;
    }

    /**
     * @return bool
     */
    private function isSensitiveKey($key, array $keys)
    {
        if (! is_string($key)) {
            return false;
        }

        $normalized = str_replace('-', '_', strtolower($key));

        foreach ($keys as $sensitive) {
            if (strpos($normalized, $sensitive) !== false) {
                return true;
            }
        }

        return false;
    }
}
