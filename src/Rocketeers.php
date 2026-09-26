<?php

namespace Rocketeers;

use Exception;

class Rocketeers
{
    protected static $baseUrlOverride = 'https://app.rocketeersapp.com/api/v1';

    protected $baseUrl;
    protected $token;

    /** @var Redactor|null */
    protected $redactor;

    public static function setBaseUrl($url)
    {
        static::$baseUrlOverride = $url;
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
        if (isset($_SERVER['HTTP_HOST'])) {
            $referrer = 'http'.(isset($_SERVER['HTTPS']) ? 's' : '').'://'."{$_SERVER['HTTP_HOST']}/{$_SERVER['REQUEST_URI']}";
        }

        try {
            $json = json_encode($this->redactor()->redactPayload($data));

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
            curl_close($ch);

            return $response;
        } catch (Exception $e) {
            return false;
        }
    }
}
