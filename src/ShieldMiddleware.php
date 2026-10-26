<?php

declare(strict_types=1);

namespace Innoartive\Shield;

/**
 * ShieldMiddleware — duck-typed middleware adapter for PSR-15-style dispatchers.
 *
 * This class works with any dispatcher that calls:
 *
 *   - `$handler->handle($request)` to get a response
 *   - `$response->withHeader($name, $value)` to apply headers
 *
 * It does **not** formally implement `Psr\Http\Server\MiddlewareInterface` because
 * the core package carries zero required runtime dependencies. If you need a
 * class that formally satisfies the PSR-15 type contract (e.g. for strict
 * dispatcher type checks), use {@see ShieldPsr15Middleware} after installing
 * the PSR interface packages.
 *
 * ## When to use this class
 *
 * Use `ShieldMiddleware` when your dispatcher calls `->handle()` and
 * `->withHeader()` but does not enforce PSR-15 interface types at runtime.
 * Many micro-frameworks and custom dispatchers work this way.
 *
 * ## When to use ShieldPsr15Middleware instead
 *
 * Use {@see ShieldPsr15Middleware} when your dispatcher requires the class to
 * formally implement `Psr\Http\Server\MiddlewareInterface`.
 *
 * ## Header replacement policy
 *
 * If the inner handler's response already contains a header that Shield would
 * set, Shield's value replaces the existing value. Disable any option with
 * `false` to preserve the application's own value for that header.
 *
 * ## Usage
 *
 * ```php
 * use Innoartive\Shield\ShieldMiddleware;
 *
 * $middleware = new ShieldMiddleware();
 * // or with options:
 * $middleware = new ShieldMiddleware([
 *     'frameOptions' => 'DENY',
 *     'hsts'         => ['maxAge' => 31536000, 'includeSubDomains' => true],
 * ]);
 * ```
 */
final class ShieldMiddleware
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
     * Process a server request and return a response with security headers applied.
     *
     * Calls `$handler->handle($request)` and applies security headers to the
     * returned response via `$response->withHeader($name, $value)`.
     *
     * This signature is intentionally compatible with PSR-15's process() method
     * but does not declare formal PSR-15 interface types.
     *
     * @param object $request  A server request object (e.g. PSR-7 ServerRequestInterface).
     * @param object $handler  A request handler exposing a handle(object): object method.
     * @return object          The response with security headers applied.
     */
    public function process(object $request, object $handler): object
    {
        $response = $handler->handle($request);
        $headers  = HeaderEmitter::build($this->config);

        foreach ($headers as $name => $value) {
            // withHeader() replaces any existing header with the same name.
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }
}
