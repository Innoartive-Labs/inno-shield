<?php

declare(strict_types=1);

/**
 * Basic InnoShield PHP example — zero-configuration security headers.
 *
 * Run this file through a web server (not CLI) to see the security headers
 * applied to the HTTP response. Use browser DevTools → Network → response
 * headers, or cURL:
 *
 *   curl -I http://localhost/examples/basic.php
 *
 * This must be the first thing that runs in your script, before any output.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Innoartive\Shield\Shield;

// Apply default security headers in one call.
Shield::protect();

// --- Your application code continues from here ---

echo "<!DOCTYPE html>\n";
echo "<html lang=\"en\">\n";
echo "<head><meta charset=\"UTF-8\"><title>InnoShield Basic Example</title></head>\n";
echo "<body>\n";
echo "<h1>InnoShield PHP — Basic Example</h1>\n";
echo "<p>Security headers have been applied. Inspect the HTTP response headers to verify.</p>\n";
echo "<pre>";

// In a browser, open DevTools → Network → this request → Response Headers.
// When accessed via CLI, Shield::headers() can be used to inspect without side effects:
$headers = Shield::headers();
foreach ($headers as $name => $value) {
    echo htmlspecialchars("{$name}: {$value}") . "\n";
}

echo "</pre>\n";
echo "</body>\n</html>\n";
