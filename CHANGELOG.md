# Changelog

All notable changes to `rocketeers-api-client` will be documented in this file

## 2.21.0 - 2026-10-12

- Redact the code snippets of a trace with `Redactor::redactCode()`, which only matches credential shapes, so indentation and lines such as `[]` survive; a private key spread over the lines of a snippet is redacted too
- Encode a report with `JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR`, so a source file with invalid UTF-8 no longer loses the whole report

## 2.20.1 - 2026-10-12

- Report to `https://api.rocketeersapp.com/v1` by default, since `app.rocketeersapp.com/api/v1` no longer serves the API

## 1.3.0 - 2026-09-08

- Redact credentials from every report before it is sent, via the new `Rocketeers\Redactor`
- Match sensitive field names as a substring, so `current_password` and `client_secret` are covered
- Match credentials that carry no field name by shape: private keys, `Authorization` headers, shell and SQL password flags, and credential-shaped URL query parameters
- Walk into JSON held in a string, so a queued job's raw body is scrubbed too
- Accept extra field names through `Rocketeers::setRedactor(new Redactor([...]))`

## 1.0.0 - 201X-XX-XX

- initial release
