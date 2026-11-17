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

            if (PHP_VERSION_ID < 80000) {
                curl_close($ch);
            }

            return $response;
        } catch (Exception $e) {
            return false;
        }
    }
}
