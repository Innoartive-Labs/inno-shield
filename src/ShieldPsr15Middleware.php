<?php

declare(strict_types=1);

namespace Innoartive\Shield;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * ShieldPsr15Middleware — formally PSR-15-compliant middleware adapter.
 *
 * This class implements `Psr\Http\Server\MiddlewareInterface` and uses correct
 * PSR-7 / PSR-15 types throughout. It requires the PSR interface packages to
 * be installed.
 *
 * ## Required packages
 *
 * Install the PSR interfaces before using this class:
 *
 * ```bash
 * composer require psr/http-server-middleware psr/http-server-handler psr/http-message
 * ```
 *
 * ## Usage
 *
 * ```php
 * use Innoartive\Shield\ShieldPsr15Middleware;
 *
 * $middleware = new ShieldPsr15Middleware();
 * // or with options:
 * $middleware = new ShieldPsr15Middleware([
 *     'frameOptions' => 'DENY',
 *     'hsts'         => ['maxAge' => 31536000, 'includeSubDomains' => true],
 * ]);
 * ```
 *
 * Add `$middleware` to your PSR-15-compatible dispatcher's middleware stack.
 *
 * ## Difference from ShieldMiddleware
 *
 * {@see ShieldMiddleware} is duck-typed (no interface required) and has zero
 * dependencies. Use it when your dispatcher does not enforce PSR-15 types.
 *
 * `ShieldPsr15Middleware` formally implements `MiddlewareInterface` and is the
 * correct choice when your dispatcher performs a strict interface check.
 *
 * ## Header replacement policy
 *
 * Shield's configured value replaces any existing value for the same header
 * name. Disable individual headers with `false` to preserve the application's
 * own value.
 *
 * ## Core dependency note
 *
 * The core package (Shield.php, Config.php, HeaderEmitter.php) does not
 * depend on PSR packages. This file is the only one that requires them.
 */
final class ShieldPsr15Middleware implements MiddlewareInterface
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
     * Apply security headers to the PSR-7 response and return it.
     *
     * {@inheritDoc}
     */
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $response = $handler->handle($request);
        $headers  = HeaderEmitter::build($this->config);

        foreach ($headers as $name => $value) {
            // withHeader() replaces any existing header with the same name.
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }
}
