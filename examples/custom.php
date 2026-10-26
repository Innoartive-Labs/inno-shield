<?php

declare(strict_types=1);

/**
 * Custom configuration example for InnoShield PHP.
 *
 * Demonstrates CSP, HSTS, custom referrer policy, and custom headers.
 * Call this before any output in a real application.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Innoartive\Shield\Shield;

Shield::protect([
    // Restrict framing to the same origin.
    'frameOptions'   => 'DENY',

    // Send no referrer information at all.
    'referrerPolicy' => 'no-referrer',

    // Enable a basic Content Security Policy.
    // Adjust these source lists to match your application.
    'contentSecurityPolicy' => [
        'default-src'              => ["'self'"],
        'script-src'               => ["'self'"],
        'style-src'                => ["'self'"],
        'img-src'                  => ["'self'", 'data:'],
        'font-src'                 => ["'self'"],
        'connect-src'              => ["'self'"],
        'object-src'               => ["'none'"],
        'base-uri'                 => ["'self'"],
        'form-action'              => ["'self'"],
        'upgrade-insecure-requests' => true,
    ],

    // Enable HSTS — only use this when your site is fully on HTTPS.
    // WARNING: Enabling HSTS prematurely can make your site inaccessible
    // over HTTP. Test in report-only mode first.
    'hsts' => [
        'maxAge'            => 31536000, // 1 year in seconds
        'includeSubDomains' => true,
        // 'preload' => true,  // Uncomment only after registering at hstspreload.org
    ],

    // Add application-specific headers.
    'customHeaders' => [
        'X-App-Version' => '1.0.0',
    ],
]);

// --- Your application continues ---

echo "<!DOCTYPE html>\n";
echo "<html lang=\"en\">\n";
echo "<head><meta charset=\"UTF-8\"><title>InnoShield Custom Example</title></head>\n";
echo "<body>\n";
echo "<h1>InnoShield PHP — Custom Configuration Example</h1>\n";
echo "<p>Custom security headers have been applied. Check the HTTP response headers.</p>\n";
echo "<pre>";

$headers = Shield::headers([
    'frameOptions'   => 'DENY',
    'referrerPolicy' => 'no-referrer',
    'contentSecurityPolicy' => [
        'default-src' => ["'self'"],
        'upgrade-insecure-requests' => true,
    ],
    'hsts' => [
        'maxAge'            => 31536000,
        'includeSubDomains' => true,
    ],
    'customHeaders' => [
        'X-App-Version' => '1.0.0',
    ],
]);

foreach ($headers as $name => $value) {
    echo htmlspecialchars("{$name}: {$value}") . "\n";
}

echo "</pre>\n";
echo "</body>\n</html>\n";
