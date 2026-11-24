<?php

namespace Rocketeers;

use Exception;

class Rocketeers
{
    protected static $baseUrlOverride = 'https://api.rocketeersapp.com/v1';

    protected $baseUrl;
    protected $token;

    /** @var Redactor|null */
    protected $redactor;

    /** @var int|null */
    protected $lastStatus;

    /** @var string|null */
    protected $lastError;

    public static function setBaseUrl($url)
    {
        static::$baseUrlOverride = $url;
    }

    /**
     * @return string
     */
    public static function baseUrl()
    {
        return static::$baseUrlOverride;
    }

    public function __construct($token)
    {
        $this->baseUrl = static::$baseUrlOverride;
        $this->token = $token;
    }

    public function setRedactor(Redactor $redactor)
    {
        $this->redactor = $redactor;

        return $this;
    }

    public function redactor()
    {
        if ($this->redactor === null) {
            $this->redactor = new Redactor;
        }

        return $this->redactor;
    }

    public function report(array $data)
    {
        try {
            $json = $this->encodeReport($data);
        } catch (Exception $e) {
            return false;
        }

        return $this->postReport($json);
    }

    /**
     * Redaction happens here, in the reporting process, whichever way the report then travels: posted
     * by postReport() or handed to a local agent that uploads it later.
     *
     * @return string|false
     */
    public function encodeReport(array $data)
    {
        return json_encode($this->redactor()->redactPayload($data), JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    }

    /**
     * @param  string  $json  A report as encoded by encodeReport().
     * @return string|false
     */
    public function postReport($json)
    {
        $this->lastStatus = null;
        $this->lastError = null;

        if (isset($_SERVER['HTTP_HOST'])) {
            $referrer = 'http'.(isset($_SERVER['HTTPS']) ? 's' : '').'://'."{$_SERVER['HTTP_HOST']}/{$_SERVER['REQUEST_URI']}";
        }

        try {
            $ch = curl_init($this->baseUrl . '/errors');
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $json,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 3,
                CURLOPT_HTTPHEADER => [
                    'Content-Type: application/json',
                    'Accept: application/json',
                    'Authorization: Bearer ' . $this->token,
                    'Referer: ' . ($referrer ?? ''),
                ],
            ]);
            $response = curl_exec($ch);

            $this->lastStatus = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE) ?: null;
            $this->lastError = $response === false ? (curl_error($ch) ?: 'The request failed.') : null;

            if (PHP_VERSION_ID < 80000) {
                curl_close($ch);
            }

            return $response;
        } catch (Exception $e) {
            $this->lastStatus = null;
            $this->lastError = $e->getMessage();

            return false;
        }
    }

    /**
     * The HTTP status of the last report posted to /errors, or null when none was posted or no
     * response came back.
     *
     * @return int|null
     */
    public function lastStatus()
    {
        return $this->lastStatus;
    }

    /**
     * Why the last post got no response at all, such as a DNS, TLS or timeout error; null when a
     * response came back, whatever its status.
     *
     * @return string|null
     */
    public function lastError()
    {
        return $this->lastError;
    }
}
