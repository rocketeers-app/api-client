<?php

/**
 * Router for `php -S` that writes every request it receives to the file named by
 * ROCKETEERS_CAPTURE_FILE, so a test can assert on the request a client really sent.
 */
file_put_contents(getenv('ROCKETEERS_CAPTURE_FILE'), json_encode([
    'method' => $_SERVER['REQUEST_METHOD'],
    'uri' => $_SERVER['REQUEST_URI'],
    'headers' => getallheaders(),
    'body' => file_get_contents('php://input'),
]));

header('Content-Type: application/json');

echo '"OK"';
