<?php

declare(strict_types=1);

namespace Innoartive\Shield;

/**
 * Shield — the primary entry point for InnoShield PHP.
 *
 * Applies HTTP security headers to the current PHP response.
 *
 * ## Basic usage (zero configuration)
 *
 * ```php
 * use Innoartive\Shield\Shield;
 *
 * Shield::protect();
 * ```
 *
 * ## Custom configuration (all options are optional)
 *
 * ```php
 * Shield::protect([
 *     'contentSecurityPolicy' => [
 *         'default-src' => ["'self'"],
 *     ],
 *     'hsts' => [
 *         'maxAge'            => 31536000,
 *         'includeSubDomains' => true,
 *     ],
 *     'frameOptions'    => 'DENY',
 *     'referrerPolicy'  => 'no-referrer',
 *     'customHeaders'   => [
 *         'X-My-App-Header' => 'value',
 *     ],
 * ]);
 * ```
 *
 * ## Disabling individual headers
 *
 * Pass `false` for any header option to suppress it entirely:
 *
 * ```php
 * Shield::protect([
 *     'frameOptions'          => false,
 *     'contentSecurityPolicy' => false,
 * ]);
 * ```
 *
 * ## Important
 *
 * Call `Shield::protect()` **before** any output is produced. PHP cannot send
 * HTTP headers once the response body has started.
 *
 * @api
 */
final class Shield
{
    /**
     * Apply security headers to the current PHP response.
     *
     * Resolves the supplied options (or the built-in defaults), validates every
     * value, builds the header set, and emits each header via PHP's global
     * `header()` function.
     *
     * @param array<string, mixed> $options
     *   Optional configuration. All keys are optional; omitted keys use their
     *   documented defaults. Passing an empty array is equivalent to calling
     *   the method with no arguments.
     *
     * @throws ShieldException
     *   If any option value is invalid, if a header value contains CR or LF
     *   characters, or if PHP headers have already been sent.
     */
    public static function protect(array $options = []): void
    {
        $config  = new Config($options);
        $headers = HeaderEmitter::build($config);
        HeaderEmitter::emit($headers);
    }

    /**
     * Return the resolved headers that `protect()` would emit without actually
     * sending them.
     *
     * This is useful for testing, debugging, and for PSR-15 middleware that
     * needs the header list to inject into a response object rather than
     * calling PHP's global `header()`.
     *
     * @param array<string, mixed> $options
     * @return array<string, string> Map of header-name => header-value.
     * @throws ShieldException If any option value is invalid.
     */
    public static function headers(array $options = []): array
    {
        $config = new Config($options);
        return HeaderEmitter::build($config);
    }
}
