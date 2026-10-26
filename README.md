# InnoShield PHP

A lightweight, framework-independent PHP security-header library inspired by the simplicity of [Express Helmet](https://helmetjs.github.io/).

[![PHP 8.1+](https://img.shields.io/badge/PHP-8.1%2B-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Install it. Import it. Call it. Move on.

```bash
composer require innoartive-labs/inno-shield-php
```

```php
use Innoartive\Shield\Shield;

Shield::protect();
```

That one call applies a sensible set of HTTP security headers to your PHP response — no configuration file, no service container, no framework required.

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Default Headers](#default-headers)
4. [Configuration Reference](#configuration-reference)
5. [Content Security Policy](#content-security-policy)
6. [HTTP Strict Transport Security](#http-strict-transport-security)
7. [Custom Headers](#custom-headers)
8. [Plain PHP Integration](#plain-php-integration)
9. [Laravel and Lumen Integration](#laravel-and-lumen-integration)
10. [PSR-15 Middleware](#psr-15-middleware)
11. [Compatibility and Deployment](#compatibility-and-deployment)
12. [Running Tests](#running-tests)
13. [Contributing](#contributing)
14. [Security Vulnerabilities](#security-vulnerabilities)
15. [License](#license)

---

## Installation

**Requirements:** PHP 8.1 or later, Composer.

```bash
composer require innoartive-labs/inno-shield-php
```

---

## Quick Start

Place this call **before** any output is produced:

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Innoartive\Shield\Shield;

Shield::protect();

// Your application code continues here.
```

To inspect which headers would be applied without emitting them (useful in tests and middleware):

```php
$headers = Shield::headers();
// Returns: ['X-Content-Type-Options' => 'nosniff', 'X-Frame-Options' => 'SAMEORIGIN', ...]
```

---

## Default Headers

`Shield::protect()` with no arguments applies the following headers. All are appropriate for general-purpose PHP applications.

| Header | Default Value | Purpose |
|--------|--------------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevents browsers from MIME-sniffing the response content type. Reduces risk of certain content-confusion attacks. |
| `X-Frame-Options` | `SAMEORIGIN` | Controls whether the page can be embedded in a frame. `SAMEORIGIN` permits framing only from the same origin, helping mitigate clickjacking. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer information sent with navigation requests. Protects URL-embedded sensitive data from leaking to third parties. |
| `X-Permitted-Cross-Domain-Policies` | `none` | Tells Adobe Flash and Acrobat not to load cross-domain policy files. Prevents those clients from making cross-domain requests on behalf of your site. |

**Not enabled by default:**

| Header | Reason |
|--------|--------|
| `Content-Security-Policy` | Requires per-application tuning. An overly strict CSP breaks existing assets. Opt in explicitly. |
| `Strict-Transport-Security` | Appropriate only when HTTPS is correctly configured. Enabling prematurely can make a site inaccessible. Opt in explicitly. |

---

## Configuration Reference

All options are optional. Pass only the keys you want to change. Unknown
top-level option names are rejected to catch configuration typos.

```php
Shield::protect([
    'contentTypeOptions'    => 'nosniff',           // string or false
    'frameOptions'          => 'SAMEORIGIN',         // 'DENY' | 'SAMEORIGIN' | false
    'referrerPolicy'        => 'strict-origin-when-cross-origin', // see values below
    'crossDomainPolicies'   => 'none',              // 'none' | 'master-only' | 'by-content-type' | 'all' | false
    'hsts'                  => false,               // array or false — see HSTS section
    'contentSecurityPolicy' => false,               // array or false — see CSP section
    'customHeaders'         => [],                  // ['Header-Name' => 'value', ...]
]);
```

### Option: `contentTypeOptions`

| Value | Description |
|-------|-------------|
| `'nosniff'` | *(default)* Emit `X-Content-Type-Options: nosniff`. |
| `false` | Omit the header entirely. |

### Option: `frameOptions`

| Value | Description |
|-------|-------------|
| `'SAMEORIGIN'` | *(default)* Allow framing from the same origin only. |
| `'DENY'` | Forbid framing from any origin. |
| `false` | Omit the header entirely. |

### Option: `referrerPolicy`

Any value from the [W3C Referrer Policy specification](https://www.w3.org/TR/referrer-policy/) is accepted:

`no-referrer`, `no-referrer-when-downgrade`, `origin`, `origin-when-cross-origin`, `same-origin`, `strict-origin`, `strict-origin-when-cross-origin` *(default)*, `unsafe-url`, `false`

### Option: `crossDomainPolicies`

| Value | Description |
|-------|-------------|
| `'none'` | *(default)* No policy files permitted. |
| `'master-only'` | Only master policy files. |
| `'by-content-type'` | Only policy files served with XML content type. |
| `'all'` | All policy files permitted. |
| `false` | Omit the header. |

---

## Content Security Policy

CSP is **disabled by default**. Enable it explicitly with a directive map:

```php
// Generate a fresh cryptographically secure nonce per request in your application:
$nonce = base64_encode(random_bytes(16));

Shield::protect([
    'contentSecurityPolicy' => [
        'default-src' => ["'self'"],
        'script-src'  => ["'self'", "'nonce-{$nonce}'"],
        'style-src'   => ["'self'"],
        'img-src'     => ["'self'", 'data:', 'https:'],
        'object-src'  => ["'none'"],
        'base-uri'    => ["'self'"],
        'form-action' => ["'self'"],
        'upgrade-insecure-requests' => true,  // boolean flag (no value)
    ],
]);
```

> **Note on Nonces:** InnoShield PHP does not generate nonces automatically. Nonces must be generated per request in your application code (as shown with `random_bytes(16)`) and passed into both `Shield::protect()` and your rendered HTML `<script nonce="...">` tags:
>
> ```html
> <script nonce="<?= htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') ?>">
>     // Inline script running safely with CSP nonce
> </script>
> ```

### Boolean flag directives

Directives that have no source list (e.g. `upgrade-insecure-requests`, `block-all-mixed-content`) are set with `true`. Set to `false` to explicitly omit a directive.

Each CSP source must be one source expression. Do not combine sources or
directives in a single string.

### Report-only mode

To test a policy before enforcing it:

```php
Shield::protect([
    'contentSecurityPolicy' => [
        'reportOnly'  => true,   // emits Content-Security-Policy-Report-Only instead
        'default-src' => ["'self'"],
    ],
]);
```

### Disabling CSP

```php
Shield::protect(['contentSecurityPolicy' => false]);
```

### CSP deployment advice

- Start with report-only mode and review violations before enforcing.
- Avoid `'unsafe-inline'` and `'unsafe-eval'` in enforced policies.
- Generate a fresh cryptographically random nonce per request when using nonce-based policies. Never reuse a fixed nonce.
- Test CSP changes in staging before production.

---

## HTTP Strict Transport Security

HSTS is **never enabled by default**. It must be explicitly configured.

> **Warning:** Once HSTS is sent, browsers will refuse HTTP connections to your domain for the duration of `max-age`. Only enable HSTS when your site correctly serves HTTPS on all paths and you are confident you will not need to revert to HTTP.

```php
Shield::protect([
    'hsts' => [
        'maxAge'            => 31536000, // required; seconds (1 year)
        'includeSubDomains' => true,     // optional; default false
        'preload'           => false,    // optional; default false — see note below
    ],
]);
```

This emits:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### HSTS preload

`preload` requires both `includeSubDomains: true` and `maxAge >= 31536000`. Submitting a site to the HSTS preload list is an irreversible action that affects all browsers. Only set `preload: true` after reading [hstspreload.org](https://hstspreload.org) and explicitly opting in.

### Disabling HSTS

```php
Shield::protect(['hsts' => false]);
```

---

## Custom Headers

Add arbitrary response headers through the `customHeaders` option:

```php
Shield::protect([
    'customHeaders' => [
        'X-App-Version'  => '2.3.1',
        'X-Robots-Tag'   => 'noindex',
        'Permissions-Policy' => 'geolocation=(), microphone=()',
    ],
]);
```

Custom headers cannot replace headers managed by Shield. Use the matching
dedicated option instead, such as `frameOptions`, `hsts`, or
`contentSecurityPolicy`.

**Validation rules:**

- Header names must follow [RFC 7230 token rules](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6): printable ASCII, no spaces or delimiters.
- Header values cannot contain control characters. Shield rejects unsafe values with a `ShieldException`.

---

## Plain PHP Integration

For a traditional PHP application, call `Shield::protect()` at the very beginning of your entry point, before any output or header calls:

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Innoartive\Shield\Shield;

// Must be called before any echo, print, or included file that produces output.
Shield::protect();

// Bootstrap your application, connect to the database, etc.
require_once __DIR__ . '/app/bootstrap.php';
```

If headers have already been sent when `Shield::protect()` is called, it throws `Innoartive\Shield\ShieldException`:

```
Cannot apply security headers: output has already been sent (output started in /path/to/file.php:12).
```

Catch it explicitly if your application needs to handle the error gracefully:

```php
use Innoartive\Shield\Shield;
use Innoartive\Shield\ShieldException;

try {
    Shield::protect();
} catch (ShieldException $e) {
    error_log('Security headers could not be applied: ' . $e->getMessage());
    // Decide how your application should proceed.
}
```

---

## Laravel and Lumen Integration

InnoShield provides a dedicated, lightweight middleware adapter for Laravel and Lumen: `Innoartive\Shield\Laravel\ShieldMiddleware`.

It follows Laravel's `handle($request, Closure $next)` middleware contract and safely attaches headers to the outgoing response without calling PHP's global `header()` function. It introduces **zero** hard runtime framework dependencies to InnoShield.

### Registration in Laravel 11+

In `bootstrap/app.php`:

```php
use Innoartive\Shield\Laravel\ShieldMiddleware;

return Application::configure(basePath: dirname(__DIR__))
    // ...
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->append(ShieldMiddleware::class);
    })
    ->create();
```

### Registration in Laravel 10 and Earlier

In `app/Http/Kernel.php`:

```php
protected $middleware = [
    // Apply globally to all incoming HTTP requests:
    \Innoartive\Shield\Laravel\ShieldMiddleware::class,
    // ...
];
```

Or register as an alias to apply only to specific route groups or controllers:

```php
// In $middlewareAliases (or $routeMiddleware):
protected $middlewareAliases = [
    'shield' => \Innoartive\Shield\Laravel\ShieldMiddleware::class,
];
```

### Registration in Lumen

In `bootstrap/app.php`:

```php
$app->middleware([
    \Innoartive\Shield\Laravel\ShieldMiddleware::class,
]);
```

### Configuring Options in Laravel & Lumen

By default, the middleware emits the default security headers. To supply custom configuration (such as CSP or HSTS), register the middleware in your service container (e.g. `AppServiceProvider`):

```php
namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Innoartive\Shield\Laravel\ShieldMiddleware;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ShieldMiddleware::class, function () {
            return new ShieldMiddleware([
                'frameOptions'   => 'DENY',
                'referrerPolicy' => 'strict-origin-when-cross-origin',
                'hsts'           => [
                    'maxAge'            => 31536000,
                    'includeSubDomains' => true,
                ],
                'contentSecurityPolicy' => [
                    'default-src' => ["'self'"],
                    'script-src'  => ["'self'"],
                    'style-src'   => ["'self'"],
                    'img-src'     => ["'self'", 'data:'],
                    'object-src'  => ["'none'"],
                ],
            ]);
        });
    }
}
```

Alternatively, create an application-specific subclass:

```php
namespace App\Http\Middleware;

use Innoartive\Shield\Laravel\ShieldMiddleware;

class SecurityHeaders extends ShieldMiddleware
{
    public function __construct()
    {
        parent::__construct([
            'frameOptions' => 'DENY',
            'hsts' => ['maxAge' => 31536000, 'includeSubDomains' => true],
        ]);
    }
}
```

### Header Replacement & Safety

- Headers are set after `$next($request)` executes, attaching directly to Laravel's `$response->headers`.
- Any existing response header that conflicts with an enabled Shield header will be replaced by Shield's value.
- To preserve an application-set header, pass `false` for that option (e.g. `'frameOptions' => false`).
- Response body, status code, redirects (e.g. 302 with `Location`), and all other headers are preserved intact.

### Framework Verification Note

The Laravel and Lumen adapter conforms to the standard `handle($request, Closure $next)` contract and has been verified against Response and HeaderBag specifications (status, redirect, custom headers, and body preservation). Because `illuminate/http` is an optional `suggest` dependency and not a mandatory runtime requirement of the core library, live execution in an application requires Laravel or Lumen installed.

---

## PSR-15 Middleware

InnoShield provides two PSR-15 middleware options depending on your project's dependency constraints:

### 1. Duck-typed Middleware (`ShieldMiddleware`)

If your dispatcher calls `handle($request)` and expects `withHeader()` on the response, but you do **not** want external PSR packages installed:

```php
use Innoartive\Shield\ShieldMiddleware;

$middleware = new ShieldMiddleware([
    'frameOptions' => 'DENY',
]);

// Works with any dispatcher using duck-typed PSR-15 semantics.
$response = $middleware->process($request, $handler);
```

### 2. Formal PSR-15 Middleware (`ShieldPsr15Middleware`)

If your dispatcher strictly enforces `Psr\Http\Server\MiddlewareInterface` compliance at runtime (e.g. Slim 4, Mezzio):

Install the standard PSR interfaces:

```bash
composer require psr/http-server-middleware psr/http-server-handler psr/http-message
```

Then register `ShieldPsr15Middleware`:

```php
use Innoartive\Shield\ShieldPsr15Middleware;

$middleware = new ShieldPsr15Middleware([
    'frameOptions' => 'SAMEORIGIN',
    'hsts'         => ['maxAge' => 31536000, 'includeSubDomains' => true],
]);

// Example with Slim 4:
// $app->add($middleware);
```

### Header Replacement Policy

- Headers are applied to the PSR-7 response object via `$response->withHeader()`.
- Shield does **not** call PHP's global `header()` function in middleware mode.
- Existing headers matching enabled Shield options are replaced; set an option to `false` to preserve the original value.
- Response status code, stream body, and unaffected headers are preserved.
- Configuration is validated upon instantiation (`__construct()`), catching configuration errors during application bootstrap rather than during request handling.

---

## Compatibility and Deployment

### PHP version support

| PHP Version | Supported |
|-------------|-----------|
| 8.5         | Yes (tested on 8.5.12) |
| 8.4         | Yes |
| 8.3         | ✓         |
| 8.2         | ✓         |
| 8.1         | ✓         |
| 8.0 and below | ✗ (strict types and named arguments require 8.1+) |

### Zero runtime dependencies

The core library (`Shield`, `Config`, `HeaderEmitter`), the duck-typed `ShieldMiddleware`, and the Laravel adapter (`Innoartive\Shield\Laravel\ShieldMiddleware`) carry **zero** required runtime dependencies.

The optional `ShieldPsr15Middleware` is the only component requiring external `psr/*` packages, keeping your vendor directory minimal and unencumbered.

### Limitations and honest notes

- **InnoShield applies security headers only.** It does not prevent SQL injection, XSS in your application code, authentication bypasses, IDOR, or any vulnerability that is not addressed by HTTP response headers.
- **HSTS is a one-way door per browser.** Test with a short `max-age` first and increase it only when you are confident.
- **CSP requires per-application tuning.** A policy that works for one site will break another. Use report-only mode and review violations before enforcing.
- **Reverse proxy headers are not automatically trusted.** If your application sits behind a proxy, configure trusted proxy handling in your own application layer rather than relying on headers like `X-Forwarded-Proto`.
- **Output buffering:** If you use `ob_start()` before `Shield::protect()`, PHP may consider headers not yet sent. This is generally fine, but test your exact SAPI and buffering configuration.

---

## Running Tests

Install development dependencies:

```bash
composer install
```

Run the full test suite:

```bash
vendor/bin/phpunit
```

Run with verbose output:

```bash
vendor/bin/phpunit --testdox
```

Check PHP syntax:

```bash
find src tests -name '*.php' -exec php -l {} \;
```

Validate Composer metadata:

```bash
composer validate --strict
```

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. Fork the repository and create a branch from `main`.
2. Write tests for any new behaviour.
3. Ensure the full test suite passes before submitting a pull request.
4. Keep the public API minimal and backward-compatible.
5. Update `CHANGELOG.md` under the `[Unreleased]` section.
6. Submit a pull request with a clear description of the change and the motivation.

This library deliberately keeps its scope narrow. Pull requests that add significant new dependencies, large feature sets, or framework-specific adapters are unlikely to be accepted in their current form — open an issue first to discuss.

---

## Security Vulnerabilities

If you discover a security vulnerability in InnoShield PHP, **do not open a public issue.**

Please contact the repository maintainers privately through GitHub with a clear
description and reproduction steps.

---

## License

MIT License — see [LICENSE](LICENSE) for the full text.

Copyright © 2026 Innoartive Labs.
