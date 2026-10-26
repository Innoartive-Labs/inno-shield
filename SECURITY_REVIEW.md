# Security Review

Reviewed: 2026-10-26

## Result

The package is suitable for use after the fixes in this review. The core API,
PSR-15 adapter, and Laravel/Lumen adapter consistently apply the same headers.

## Fixed

| Severity | Finding | Resolution |
|---|---|---|
| High | CSP source strings could contain whitespace or `;`, allowing a dynamically supplied value to add source tokens or directives. | CSP sources must now be one token and reject separators. |
| Medium | HSTS flags and CSP `reportOnly` used loose boolean casts, so strings such as `"false"` enabled them. | These settings now require `bool` values. |
| Medium | `customHeaders` could overwrite a built-in security header, including with a different casing. | Managed header names are rejected case-insensitively. |
| Low | Header values rejected only CR/LF, not other unsafe control characters. | All disallowed HTTP control characters are rejected. |
| Low | Unknown option keys were ignored, making security configuration typos silent. | Top-level and HSTS configuration keys are now strict. |

## Verification

- PHPUnit: 132 tests, 240 assertions, all passing.
- PHP syntax checks passed for modified source files.
- `composer validate --strict` passed.
- `composer audit --locked` found no known dependency advisories.

## Operational guidance

- Configure CSP for the application and start with `reportOnly: true`.
- Enable HSTS only after HTTPS works for every path and required subdomain.
- Generate CSP nonces per request; never use a fixed nonce.
- Consider adding `Permissions-Policy` through `customHeaders` where relevant.

## Remaining scope

This package sets response headers. It does not sanitize HTML, prevent SQL
injection, manage CORS, or replace application authentication and authorization.
