# Changelog

All notable changes to `rocketeers-api-client` will be documented in this file

## 1.3.0 - 2026-09-08

- Redact credentials from every report before it is sent, via the new `Rocketeers\Redactor`
- Match sensitive field names as a substring, so `current_password` and `client_secret` are covered
- Match credentials that carry no field name by shape: private keys, `Authorization` headers, shell and SQL password flags, and credential-shaped URL query parameters
- Walk into JSON held in a string, so a queued job's raw body is scrubbed too
- Accept extra field names through `Rocketeers::setRedactor(new Redactor([...]))`

## 1.0.0 - 201X-XX-XX

- initial release
