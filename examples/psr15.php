<?php

declare(strict_types=1);

/**
 * Example: Using InnoShield with PSR-15 dispatchers (Slim, Mezzio, etc.).
 *
 * InnoShield provides two PSR-15 middleware choices:
 *
 * 1. Innoartive\Shield\ShieldMiddleware (Duck-typed, zero runtime dependencies)
 *    Works with any framework or dispatcher that calls handle($request) and withHeader().
 *
 * 2. Innoartive\Shield\ShieldPsr15Middleware (Formally implements MiddlewareInterface)
 *    Strictly implements Psr\Http\Server\MiddlewareInterface with typed signatures.
 *    Requires composer packages: psr/http-server-middleware, psr/http-server-handler, psr/http-message.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Innoartive\Shield\ShieldMiddleware;
use Innoartive\Shield\ShieldPsr15Middleware;

// ---------------------------------------------------------------------------
// 1. Duck-typed Middleware (Innoartive\Shield\ShieldMiddleware)
// ---------------------------------------------------------------------------
// Use when your dispatcher calls process() or handle() duck-typed, without
// requiring strict type declarations or external PSR dependencies:

$duckMiddleware = new ShieldMiddleware([
    'frameOptions'   => 'DENY',
    'referrerPolicy' => 'strict-origin-when-cross-origin',
]);

// In your application / dispatcher stack:
// $app->add($duckMiddleware);


// ---------------------------------------------------------------------------
// 2. Formal PSR-15 Middleware (Innoartive\Shield\ShieldPsr15Middleware)
// ---------------------------------------------------------------------------
// Use when your dispatcher enforces MiddlewareInterface compliance:
//
// Requires:
//   composer require psr/http-server-middleware psr/http-server-handler psr/http-message

if (interface_exists(\Psr\Http\Server\MiddlewareInterface::class)) {
    $psr15Middleware = new ShieldPsr15Middleware([
        'frameOptions'   => 'SAMEORIGIN',
        'referrerPolicy' => 'strict-origin-when-cross-origin',
        'hsts'           => [
            'maxAge'            => 31536000,
            'includeSubDomains' => true,
        ],
        'contentSecurityPolicy' => [
            'default-src' => ["'self'"],
            'upgrade-insecure-requests' => true,
        ],
    ]);

    // Example in Slim Framework 4:
    // $app->add($psr15Middleware);
}

echo "PSR-15 middleware example loaded successfully.\n";
