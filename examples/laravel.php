<?php

declare(strict_types=1);

/**
 * Example: Using InnoShield with Laravel or Lumen.
 *
 * InnoShield provides a dedicated middleware adapter for Laravel and Lumen:
 * Innoartive\Shield\Laravel\ShieldMiddleware.
 *
 * It attaches HTTP security headers to the outgoing response using Laravel's
 * handle($request, Closure $next) middleware signature, without introducing
 * hard framework dependencies to the InnoShield package.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Innoartive\Shield\Laravel\ShieldMiddleware;

// ---------------------------------------------------------------------------
// 1. Laravel 11+ Registration (bootstrap/app.php)
// ---------------------------------------------------------------------------
/*
use Innoartive\Shield\Laravel\ShieldMiddleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // Append globally to all requests:
        $middleware->append(ShieldMiddleware::class);
    })
    ->create();
*/

// ---------------------------------------------------------------------------
// 2. Laravel 10 and Earlier Registration (app/Http/Kernel.php)
// ---------------------------------------------------------------------------
/*
namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    // Global middleware stack:
    protected $middleware = [
        \Innoartive\Shield\Laravel\ShieldMiddleware::class,
        // ...
    ];

    // Or route-specific alias:
    protected $middlewareAliases = [
        'shield' => \Innoartive\Shield\Laravel\ShieldMiddleware::class,
    ];
}
*/

// ---------------------------------------------------------------------------
// 3. Lumen Registration (bootstrap/app.php)
// ---------------------------------------------------------------------------
/*
$app->middleware([
    \Innoartive\Shield\Laravel\ShieldMiddleware::class,
]);
*/

// ---------------------------------------------------------------------------
// 4. Custom Configuration via Service Container (e.g. AppServiceProvider)
// ---------------------------------------------------------------------------
/*
namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Innoartive\Shield\Laravel\ShieldMiddleware;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Bind ShieldMiddleware with custom security options:
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
*/

echo "This file provides copy-paste ready examples for Laravel & Lumen.\n";
echo "See comments above for registration in Laravel 11+, Laravel 10-, and Lumen.\n";
