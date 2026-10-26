<?php

declare(strict_types=1);

namespace Innoartive\Shield\Tests;

use Innoartive\Shield\Shield;
use Innoartive\Shield\ShieldException;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the primary Shield public API.
 *
 * NOTE: Shield::protect() calls PHP's global header() function, which is a
 * no-op in CLI mode (where PHPUnit runs). We therefore test default behavior
 * through Shield::headers() which returns the resolved header array without
 * emitting anything. The test for the headers-sent guard uses ob_start() to
 * produce output and trigger the condition in an SAPI-aware way where possible.
 */
final class ShieldTest extends TestCase
{
    // -----------------------------------------------------------------------
    // Shield::headers() — safe inspection without side-effects
    // -----------------------------------------------------------------------

    public function testHeadersReturnsDefaultSet(): void
    {
        $headers = Shield::headers();

        $this->assertArrayHasKey('X-Content-Type-Options', $headers);
        $this->assertArrayHasKey('X-Frame-Options', $headers);
        $this->assertArrayHasKey('Referrer-Policy', $headers);
        $this->assertArrayHasKey('X-Permitted-Cross-Domain-Policies', $headers);
    }

    public function testHeadersDefaultValuesAreCorrect(): void
    {
        $headers = Shield::headers();

        $this->assertSame('nosniff', $headers['X-Content-Type-Options']);
        $this->assertSame('SAMEORIGIN', $headers['X-Frame-Options']);
        $this->assertSame('strict-origin-when-cross-origin', $headers['Referrer-Policy']);
        $this->assertSame('none', $headers['X-Permitted-Cross-Domain-Policies']);
    }

    public function testHeadersWithNoArgumentsDoesNotIncludeHsts(): void
    {
        $headers = Shield::headers();

        $this->assertArrayNotHasKey('Strict-Transport-Security', $headers);
    }

    public function testHeadersWithNoArgumentsDoesNotIncludeCsp(): void
    {
        $headers = Shield::headers();

        $this->assertArrayNotHasKey('Content-Security-Policy', $headers);
        $this->assertArrayNotHasKey('Content-Security-Policy-Report-Only', $headers);
    }

    // -----------------------------------------------------------------------
    // Customisation via options
    // -----------------------------------------------------------------------

    public function testCustomFrameOptions(): void
    {
        $headers = Shield::headers(['frameOptions' => 'DENY']);
        $this->assertSame('DENY', $headers['X-Frame-Options']);
    }

    public function testDisablingFrameOptions(): void
    {
        $headers = Shield::headers(['frameOptions' => false]);
        $this->assertArrayNotHasKey('X-Frame-Options', $headers);
    }

    public function testCustomReferrerPolicy(): void
    {
        $headers = Shield::headers(['referrerPolicy' => 'no-referrer']);
        $this->assertSame('no-referrer', $headers['Referrer-Policy']);
    }

    public function testHstsEnabledWithExplicitConfig(): void
    {
        $headers = Shield::headers([
            'hsts' => ['maxAge' => 31536000],
        ]);

        $this->assertArrayHasKey('Strict-Transport-Security', $headers);
        $this->assertSame('max-age=31536000', $headers['Strict-Transport-Security']);
    }

    public function testCspEnabled(): void
    {
        $headers = Shield::headers([
            'contentSecurityPolicy' => [
                'default-src' => ["'self'"],
                'script-src'  => ["'self'", "'unsafe-inline'"],
            ],
        ]);

        $this->assertArrayHasKey('Content-Security-Policy', $headers);
        $this->assertStringContainsString("default-src 'self'", $headers['Content-Security-Policy']);
    }

    public function testCustomHeadersAreIncluded(): void
    {
        $headers = Shield::headers([
            'customHeaders' => ['X-App-Version' => '1.0.0'],
        ]);

        $this->assertArrayHasKey('X-App-Version', $headers);
        $this->assertSame('1.0.0', $headers['X-App-Version']);
    }

    // -----------------------------------------------------------------------
    // Validation errors propagate correctly
    // -----------------------------------------------------------------------

    public function testInvalidFrameOptionsThrowsShieldException(): void
    {
        $this->expectException(ShieldException::class);
        Shield::headers(['frameOptions' => 'INVALID']);
    }

    public function testInvalidReferrerPolicyThrowsShieldException(): void
    {
        $this->expectException(ShieldException::class);
        Shield::headers(['referrerPolicy' => 'not-a-policy']);
    }

    public function testCrLfInCustomHeaderValueThrowsShieldException(): void
    {
        $this->expectException(ShieldException::class);
        Shield::headers([
            'customHeaders' => [
                'X-Injected' => "value\r\nEvil: header",
            ],
        ]);
    }

    public function testHstsMissingMaxAgeThrowsShieldException(): void
    {
        $this->expectException(ShieldException::class);
        Shield::headers(['hsts' => []]);
    }

    public function testHstsPreloadWithoutIncludeSubDomainsThrowsShieldException(): void
    {
        $this->expectException(ShieldException::class);
        Shield::headers([
            'hsts' => [
                'maxAge'  => 31536000,
                'preload' => true,
            ],
        ]);
    }

    // -----------------------------------------------------------------------
    // Shield::protect() — side-effect API
    // -----------------------------------------------------------------------

    public function testProtectRunsWithoutThrowingInCliMode(): void
    {
        // In CLI mode headers_sent() is false, so protect() should complete
        // without throwing. The actual header() calls are no-ops in CLI.
        $this->expectNotToPerformAssertions();
        Shield::protect();
    }

    public function testProtectWithOptionsRunsWithoutThrowingInCliMode(): void
    {
        $this->expectNotToPerformAssertions();
        Shield::protect([
            'frameOptions'  => 'DENY',
            'referrerPolicy' => 'no-referrer',
        ]);
    }

    public function testProtectThrowsShieldExceptionForInvalidConfig(): void
    {
        $this->expectException(ShieldException::class);
        Shield::protect(['frameOptions' => 'NOT_VALID']);
    }

    // -----------------------------------------------------------------------
    // Return type contract
    // -----------------------------------------------------------------------

    public function testHeadersReturnsArray(): void
    {
        $result = Shield::headers();
        $this->assertIsArray($result);
    }

    public function testAllHeaderValuesAreStrings(): void
    {
        $headers = Shield::headers([
            'hsts' => ['maxAge' => 31536000, 'includeSubDomains' => true],
            'contentSecurityPolicy' => [
                'default-src' => ["'self'"],
                'upgrade-insecure-requests' => true,
            ],
        ]);

        foreach ($headers as $name => $value) {
            $this->assertIsString($name, "Header name must be string, got: " . gettype($name));
            $this->assertIsString($value, "Header value for {$name} must be string, got: " . gettype($value));
        }
    }

    // -----------------------------------------------------------------------
    // Zero-output contract
    // -----------------------------------------------------------------------

    public function testProtectProducesNoOutput(): void
    {
        ob_start();
        Shield::protect();
        $output = ob_get_clean();

        $this->assertSame('', $output);
    }

    public function testHeadersProducesNoOutput(): void
    {
        ob_start();
        Shield::headers();
        $output = ob_get_clean();

        $this->assertSame('', $output);
    }
}
