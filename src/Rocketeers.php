<?php

namespace Rocketeers;

use Exception;

class Rocketeers
{
    protected $baseUrl;
    protected $token;

    public function __construct($token)
    {
        $this->baseUrl = 'https://rocketeers.app/api/v1';
        $this->token = $token;
    }

    public function report(array $data)
    {
        if (isset($_SERVER['HTTP_HOST'])) {
            $referrer = 'http'.(isset($_SERVER['HTTPS']) ? 's' : '').'://'."{$_SERVER['HTTP_HOST']}/{$_SERVER['REQUEST_URI']}";
        }

        try {
            $json = json_encode($data);

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
