# Changelog

All notable changes to InnoShield PHP will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Changed

- CI now tests PHP 8.1 through 8.5.
- Package metadata and documentation are ready for Packagist publication.
- Configuration is now strict: unknown top-level and HSTS keys are rejected.
- HSTS and CSP boolean settings now require real booleans.
- Custom headers cannot replace headers managed by Shield.

### Security

- CSP source values reject token and directive separators.
- Custom header values reject all unsafe control characters.

### Added

- `Shield::protect()` — zero-configuration entry point that applies a default
  set of HTTP security headers to the current PHP response.
- `Shield::headers()` — inspection method that returns the resolved header map
  without emitting anything (useful for testing and PSR-15 middleware).
- Default security headers applied by `Shield::protect()`:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `X-Permitted-Cross-Domain-Policies: none`
- Optional Content Security Policy support via `contentSecurityPolicy` option.
  - Structured directive configuration (array of sources per directive).
  - Boolean flag directives (e.g. `upgrade-insecure-requests`).
  - Report-only mode via `reportOnly: true`.
  - Validation of directive names and rejection of CR/LF in values.
- Optional HSTS support via `hsts` option (explicit opt-in; never enabled by
  default).
  - `maxAge` validation (non-negative integer required).
  - `includeSubDomains` and `preload` flags with consistency checks.
  - Preload requires `includeSubDomains` and `maxAge >= 31536000`.
- Custom headers via `customHeaders` option with RFC 7230 header name
  validation and CR/LF rejection.
- Any header can be individually disabled by passing `false` as its option
  value.
- `ShieldException` — typed exception thrown for invalid configuration or
  unsafe header values.
- `ShieldMiddleware` — duck-typed, zero-runtime-dependency PSR-15-style middleware
  adapter. Applies security headers to response objects via `withHeader()` without
  calling PHP's global `header()`.
- `Innoartive\Shield\ShieldPsr15Middleware` — formal `Psr\Http\Server\MiddlewareInterface`
  implementation with strict PSR-7/PSR-15 type declarations.
- `Innoartive\Shield\Laravel\ShieldMiddleware` — Laravel and Lumen middleware adapter
  supporting `handle($request, Closure $next)` post-processing and safe response header
  attachment with zero hard framework dependencies.
- Integration examples:
  - `examples/basic.php` — Plain PHP zero-config usage.
  - `examples/custom.php` — Plain PHP with CSP, HSTS, and custom headers.
  - `examples/laravel.php` — Laravel 11+, Laravel 10-, Lumen, and container binding.
  - `examples/psr15.php` — PSR-15 dispatchers (duck-typed and formal).
- Comprehensive test suite expansion:
  - `tests/ShieldPsr15MiddlewareTest.php` for PSR-15 interface compliance and header preservation.
  - `tests/LaravelShieldMiddlewareTest.php` for Laravel and Lumen middleware handling.
- GitHub Actions CI workflow testing PHP 8.1 through 8.5.

---

[Unreleased]: https://github.com/Innoartive-Labs/inno-shield/commits/main
