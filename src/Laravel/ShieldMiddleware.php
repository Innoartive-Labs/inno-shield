<?php

declare(strict_types=1);

namespace Innoartive\Shield\Laravel;

use Closure;
use Innoartive\Shield\Config;
use Innoartive\Shield\HeaderEmitter;
use Innoartive\Shield\ShieldException;

/**
 * ShieldMiddleware — Laravel and Lumen middleware adapter for InnoShield PHP.
 *
 * Applies HTTP security headers to the outgoing response using Laravel's
 * middleware contract. Works identically in Lumen, which uses the same
 * middleware signature.
 *
 * ## Registration
 *
 * ### Laravel — global middleware (app/Http/Kernel.php)
 *
 * ```php
 * // In App\Http\Kernel::$middleware:
 * protected $middleware = [
 *     \Innoartive\Shield\Laravel\ShieldMiddleware::class,
 *     // ...
 * ];
 * ```
 *
 * Or register it as a named middleware and apply selectively:
 *
 * ```php
 * // In App\Http\Kernel::$middlewareAliases (Laravel 10+) or $routeMiddleware:
 * protected $middlewareAliases = [
 *     'shield' => \Innoartive\Shield\Laravel\ShieldMiddleware::class,
 * ];
 * ```
 *
 * ### Laravel 11+ (bootstrap/app.php)
 *
 * ```php
 * ->withMiddleware(function (Middleware $middleware) {
 *     $middleware->append(\Innoartive\Shield\Laravel\ShieldMiddleware::class);
 * })
 * ```
 *
 * ### Lumen (bootstrap/app.php)
 *
 * ```php
 * $app->middleware([
 *     \Innoartive\Shield\Laravel\ShieldMiddleware::class,
 * ]);
 * ```
 *
 * ## Configuration
 *
 * The middleware can be configured by extending this class or by binding a
 * custom subclass in the service container. The simplest approach is
 * constructor injection via a service provider:
 *
 * ```php
 * // In a service provider:
 * $this->app->bind(\Innoartive\Shield\Laravel\ShieldMiddleware::class, function () {
 *     return new \Innoartive\Shield\Laravel\ShieldMiddleware([
 *         'frameOptions'  => 'DENY',
 *         'referrerPolicy' => 'no-referrer',
 *         'hsts'          => ['maxAge' => 31536000, 'includeSubDomains' => true],
 *     ]);
 * });
 * ```
 *
 * ## Dependency note
 *
 * This class does not require `illuminate/http` or any other Laravel package
 * as a Composer dependency of the InnoShield core. It uses only PHP's standard
 * `Closure` type. Laravel's `$request` and `$response` objects are accepted
 * as generic objects — the middleware works at runtime because Laravel passes
 * the correct types to the `handle()` method.
 *
 * If you want strict type safety, install `illuminate/http` and use
 * `\Illuminate\Http\Request` and `\Illuminate\Http\Response` as type hints.
 *
 * ## Header replacement policy
 *
 * Security headers are applied via `$response->header($name, $value)`,
 * which replaces any existing header with the same name. To preserve an
 * existing application header, disable the corresponding Shield option with
 * `false`.
 *
 * ## What this middleware does NOT do
 *
 * - It does not call PHP's global `header()` function.
 * - It does not modify cookies, sessions, or authentication state.
 * - It does not redirect requests.
 * - It does not claim to protect against SQL injection, XSS in application
 *   code, or any vulnerability outside the scope of HTTP response headers.
 */
class ShieldMiddleware
{
    private readonly Config $config;

    /**
     * @param array<string, mixed> $options Same options accepted by Shield::protect().
     * @throws ShieldException If any option is invalid.
     */
    public function __construct(array $options = [])
    {
        $this->config = new Config($options);
    }

    /**
     * Handle an incoming request.
     *
     * This method follows Laravel's and Lumen's middleware contract:
     *   handle(Request $request, Closure $next): Response
     *
     * Type hints are kept as `object` / `mixed` to avoid a hard dependency on
     * `illuminate/http`. At runtime Laravel and Lumen pass the correct types.
     *
     * @param object  $request The incoming HTTP request.
     * @param Closure $next    The next middleware or route handler.
     * @return mixed           The HTTP response with security headers applied.
     */
    public function handle(object $request, Closure $next): mixed
    {
        /** @var object $response */
        $response = $next($request);

        $headers = HeaderEmitter::build($this->config);

        foreach ($headers as $name => $value) {
            if (isset($response->headers) && is_object($response->headers) && method_exists($response->headers, 'set')) {
                // Standard Laravel/Lumen/Symfony response with ResponseHeaderBag.
                $response->headers->set($name, $value, true);
            } elseif (is_object($response) && method_exists($response, 'header')) {
                // Laravel response object exposing header($name, $value, $replace = true).
                $response->header($name, $value, true);
            } elseif (is_object($response) && method_exists($response, 'withHeader')) {
                // PSR-7 compatible response (e.g. Octane PSR-7 bridge).
                $response = $response->withHeader($name, $value);
            }
        }

        return $response;
    }
}
