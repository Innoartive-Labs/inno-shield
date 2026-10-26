<?php

declare(strict_types=1);

namespace Innoartive\Shield\Tests;

use Innoartive\Shield\Config;
use Innoartive\Shield\HeaderEmitter;
use Innoartive\Shield\ShieldException;
use PHPUnit\Framework\TestCase;

/**
 * Tests for HeaderEmitter — header building and CSP/HSTS string generation.
 */
final class HeaderEmitterTest extends TestCase
{
    // -----------------------------------------------------------------------
    // Default header set
    // -----------------------------------------------------------------------

    public function testDefaultHeadersContainExpectedKeys(): void
    {
        $config  = new Config();
        $headers = HeaderEmitter::build($config);

        $this->assertArrayHasKey('X-Content-Type-Options', $headers);
        $this->assertArrayHasKey('X-Frame-Options', $headers);
        $this->assertArrayHasKey('Referrer-Policy', $headers);
        $this->assertArrayHasKey('X-Permitted-Cross-Domain-Policies', $headers);
    }

    public function testDefaultHeadersDoNotContainHsts(): void
    {
        $config  = new Config();
        $headers = HeaderEmitter::build($config);

        $this->assertArrayNotHasKey('Strict-Transport-Security', $headers);
    }

    public function testDefaultHeadersDoNotContainCsp(): void
    {
        $config  = new Config();
        $headers = HeaderEmitter::build($config);

        $this->assertArrayNotHasKey('Content-Security-Policy', $headers);
        $this->assertArrayNotHasKey('Content-Security-Policy-Report-Only', $headers);
    }

    public function testDefaultHeaderValues(): void
    {
        $config  = new Config();
        $headers = HeaderEmitter::build($config);

        $this->assertSame('nosniff', $headers['X-Content-Type-Options']);
        $this->assertSame('SAMEORIGIN', $headers['X-Frame-Options']);
        $this->assertSame('strict-origin-when-cross-origin', $headers['Referrer-Policy']);
        $this->assertSame('none', $headers['X-Permitted-Cross-Domain-Policies']);
    }

    // -----------------------------------------------------------------------
    // Disabling individual headers
    // -----------------------------------------------------------------------

    public function testDisablingFrameOptionsOmitsHeader(): void
    {
        $config  = new Config(['frameOptions' => false]);
        $headers = HeaderEmitter::build($config);

        $this->assertArrayNotHasKey('X-Frame-Options', $headers);
    }

    public function testDisablingContentTypeOptionsOmitsHeader(): void
    {
        $config  = new Config(['contentTypeOptions' => false]);
        $headers = HeaderEmitter::build($config);

        $this->assertArrayNotHasKey('X-Content-Type-Options', $headers);
    }

    public function testDisablingReferrerPolicyOmitsHeader(): void
    {
        $config  = new Config(['referrerPolicy' => false]);
        $headers = HeaderEmitter::build($config);

        $this->assertArrayNotHasKey('Referrer-Policy', $headers);
    }

    public function testDisablingCrossDomainPoliciesOmitsHeader(): void
    {
        $config  = new Config(['crossDomainPolicies' => false]);
        $headers = HeaderEmitter::build($config);

        $this->assertArrayNotHasKey('X-Permitted-Cross-Domain-Policies', $headers);
    }

    // -----------------------------------------------------------------------
    // HSTS header value generation
    // -----------------------------------------------------------------------

    public function testHstsBasicMaxAge(): void
    {
        $config  = new Config(['hsts' => ['maxAge' => 31536000]]);
        $headers = HeaderEmitter::build($config);

        $this->assertArrayHasKey('Strict-Transport-Security', $headers);
        $this->assertSame('max-age=31536000', $headers['Strict-Transport-Security']);
    }

    public function testHstsWithIncludeSubDomains(): void
    {
        $config  = new Config([
            'hsts' => [
                'maxAge'            => 31536000,
                'includeSubDomains' => true,
            ],
        ]);
        $headers = HeaderEmitter::build($config);

        $this->assertSame('max-age=31536000; includeSubDomains', $headers['Strict-Transport-Security']);
    }

    public function testHstsWithPreload(): void
    {
        $config  = new Config([
            'hsts' => [
                'maxAge'            => 31536000,
                'includeSubDomains' => true,
                'preload'           => true,
            ],
        ]);
        $headers = HeaderEmitter::build($config);

        $this->assertSame(
            'max-age=31536000; includeSubDomains; preload',
            $headers['Strict-Transport-Security']
        );
    }

    // -----------------------------------------------------------------------
    // CSP header value generation
    // -----------------------------------------------------------------------

    public function testCspBasicDirective(): void
    {
        $config  = new Config([
            'contentSecurityPolicy' => [
                'default-src' => ["'self'"],
            ],
        ]);
        $headers = HeaderEmitter::build($config);

        $this->assertArrayHasKey('Content-Security-Policy', $headers);
        $this->assertSame("default-src 'self'", $headers['Content-Security-Policy']);
    }

    public function testCspMultipleDirectives(): void
    {
        $config  = new Config([
            'contentSecurityPolicy' => [
                'default-src' => ["'self'"],
                'img-src'     => ["'self'", 'data:', 'https:'],
                'script-src'  => ["'self'", "'nonce-abc123'"],
            ],
        ]);
        $headers = HeaderEmitter::build($config);

        $value = $headers['Content-Security-Policy'];
        $this->assertStringContainsString("default-src 'self'", $value);
        $this->assertStringContainsString("img-src 'self' data: https:", $value);
        $this->assertStringContainsString("script-src 'self' 'nonce-abc123'", $value);
    }

    public function testCspBooleanFlagDirective(): void
    {
        $config  = new Config([
            'contentSecurityPolicy' => [
                'upgrade-insecure-requests' => true,
            ],
        ]);
        $headers = HeaderEmitter::build($config);

        $this->assertSame('upgrade-insecure-requests', $headers['Content-Security-Policy']);
    }

    public function testCspFalseBooleanDirectiveIsOmitted(): void
    {
        $config  = new Config([
            'contentSecurityPolicy' => [
                'upgrade-insecure-requests' => false,
                'default-src'               => ["'self'"],
            ],
        ]);
        $headers = HeaderEmitter::build($config);

        $this->assertStringNotContainsString('upgrade-insecure-requests', $headers['Content-Security-Policy']);
    }

    public function testCspReportOnlyMode(): void
    {
        $config  = new Config([
            'contentSecurityPolicy' => [
                'reportOnly'  => true,
                'default-src' => ["'self'"],
            ],
        ]);
        $headers = HeaderEmitter::build($config);

        $this->assertArrayHasKey('Content-Security-Policy-Report-Only', $headers);
        $this->assertArrayNotHasKey('Content-Security-Policy', $headers);
    }

    public function testCspEmptySourceListProducesDirectiveWithNoValue(): void
    {
        $config  = new Config([
            'contentSecurityPolicy' => [
                'sandbox' => [],
            ],
        ]);
        $headers = HeaderEmitter::build($config);

        $this->assertSame('sandbox', $headers['Content-Security-Policy']);
    }

    // -----------------------------------------------------------------------
    // Custom headers
    // -----------------------------------------------------------------------

    public function testCustomHeadersAreEmitted(): void
    {
        $config  = new Config([
            'customHeaders' => [
                'X-My-Custom-Header' => 'custom-value',
            ],
        ]);
        $headers = HeaderEmitter::build($config);

        $this->assertArrayHasKey('X-My-Custom-Header', $headers);
        $this->assertSame('custom-value', $headers['X-My-Custom-Header']);
    }

    public function testCustomHeadersCannotOverrideDefaults(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['customHeaders' => ['X-Frame-Options' => 'DENY']]);
    }

    // -----------------------------------------------------------------------
    // emit() — headers_sent guard
    // -----------------------------------------------------------------------

    public function testEmitThrowsWhenHeadersAlreadySent(): void
    {
        $phpBinary = PHP_BINARY;
        $autoload  = str_replace('\\', '/', (string) realpath(__DIR__ . '/../vendor/autoload.php'));

        $code = "require '{$autoload}';"
            . " echo 'sent-output';"
            . " while (ob_get_level() > 0) { ob_end_flush(); }"
            . " flush();"
            . " try {"
            . "     \\Innoartive\\Shield\\HeaderEmitter::emit(['X-Content-Type-Options' => 'nosniff']);"
            . "     echo 'NO_EXCEPTION';"
            . " } catch (\\Innoartive\\Shield\\ShieldException \$e) {"
            . "     echo 'SHIELD_EXCEPTION: ' . \$e->getMessage();"
            . " }";

        $process = proc_open(
            [$phpBinary, '-r', $code],
            [
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes
        );

        $this->assertIsResource($process);

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        $this->assertStringContainsString('SHIELD_EXCEPTION: Cannot apply security headers: output has already been sent', $stdout);
        $this->assertStringContainsString('Call Shield::protect() before any output is produced.', $stdout);
    }
}
