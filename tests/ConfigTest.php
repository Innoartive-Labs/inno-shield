<?php

declare(strict_types=1);

namespace Innoartive\Shield\Tests;

use Innoartive\Shield\Config;
use Innoartive\Shield\ShieldException;
use PHPUnit\Framework\TestCase;

/**
 * Tests for Config — option resolution, validation, and defaults.
 */
final class ConfigTest extends TestCase
{
    // -----------------------------------------------------------------------
    // Default values
    // -----------------------------------------------------------------------

    public function testDefaultsReturnExpectedKeys(): void
    {
        $defaults = Config::defaults();

        $this->assertArrayHasKey('contentTypeOptions', $defaults);
        $this->assertArrayHasKey('frameOptions', $defaults);
        $this->assertArrayHasKey('referrerPolicy', $defaults);
        $this->assertArrayHasKey('crossDomainPolicies', $defaults);
        $this->assertArrayHasKey('hsts', $defaults);
        $this->assertArrayHasKey('contentSecurityPolicy', $defaults);
        $this->assertArrayHasKey('customHeaders', $defaults);
    }

    public function testDefaultConfigHasExpectedValues(): void
    {
        $config = new Config();

        $this->assertSame('nosniff', $config->getContentTypeOptions());
        $this->assertSame('SAMEORIGIN', $config->getFrameOptions());
        $this->assertSame('strict-origin-when-cross-origin', $config->getReferrerPolicy());
        $this->assertSame('none', $config->getCrossDomainPolicies());
        $this->assertFalse($config->getHsts());
        $this->assertFalse($config->getCsp());
        $this->assertFalse($config->isCspReportOnly());
        $this->assertSame([], $config->getCustomHeaders());
    }

    // -----------------------------------------------------------------------
    // contentTypeOptions
    // -----------------------------------------------------------------------

    public function testContentTypeOptionsAcceptsNosniff(): void
    {
        $config = new Config(['contentTypeOptions' => 'nosniff']);
        $this->assertSame('nosniff', $config->getContentTypeOptions());
    }

    public function testContentTypeOptionsAcceptsFalse(): void
    {
        $config = new Config(['contentTypeOptions' => false]);
        $this->assertFalse($config->getContentTypeOptions());
    }

    public function testContentTypeOptionsRejectsInvalidValue(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['contentTypeOptions' => 'invalid']);
    }

    public function testContentTypeOptionsRejectsNonString(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['contentTypeOptions' => 42]);
    }

    // -----------------------------------------------------------------------
    // frameOptions
    // -----------------------------------------------------------------------

    public function testFrameOptionsAcceptsDeny(): void
    {
        $config = new Config(['frameOptions' => 'DENY']);
        $this->assertSame('DENY', $config->getFrameOptions());
    }

    public function testFrameOptionsAcceptsSameOrigin(): void
    {
        $config = new Config(['frameOptions' => 'SAMEORIGIN']);
        $this->assertSame('SAMEORIGIN', $config->getFrameOptions());
    }

    public function testFrameOptionsAcceptsFalse(): void
    {
        $config = new Config(['frameOptions' => false]);
        $this->assertFalse($config->getFrameOptions());
    }

    public function testFrameOptionsRejectsInvalidValue(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['frameOptions' => 'ALLOWALL']);
    }

    public function testFrameOptionsRejectsCrLf(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['frameOptions' => "DENY\r\nX-Injected: header"]);
    }

    // -----------------------------------------------------------------------
    // referrerPolicy
    // -----------------------------------------------------------------------

    public function testReferrerPolicyAcceptsValidValues(): void
    {
        $cases = [
            'no-referrer',
            'no-referrer-when-downgrade',
            'origin',
            'origin-when-cross-origin',
            'same-origin',
            'strict-origin',
            'strict-origin-when-cross-origin',
            'unsafe-url',
        ];

        foreach ($cases as $policy) {
            $config = new Config(['referrerPolicy' => $policy]);
            $this->assertSame($policy, $config->getReferrerPolicy(), "Failed for policy: {$policy}");
        }
    }

    public function testReferrerPolicyAcceptsFalse(): void
    {
        $config = new Config(['referrerPolicy' => false]);
        $this->assertFalse($config->getReferrerPolicy());
    }

    public function testReferrerPolicyRejectsInvalidValue(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['referrerPolicy' => 'send-everything']);
    }

    // -----------------------------------------------------------------------
    // crossDomainPolicies
    // -----------------------------------------------------------------------

    public function testCrossDomainPoliciesAcceptsNone(): void
    {
        $config = new Config(['crossDomainPolicies' => 'none']);
        $this->assertSame('none', $config->getCrossDomainPolicies());
    }

    public function testCrossDomainPoliciesAcceptsAll(): void
    {
        $config = new Config(['crossDomainPolicies' => 'all']);
        $this->assertSame('all', $config->getCrossDomainPolicies());
    }

    public function testCrossDomainPoliciesAcceptsFalse(): void
    {
        $config = new Config(['crossDomainPolicies' => false]);
        $this->assertFalse($config->getCrossDomainPolicies());
    }

    public function testCrossDomainPoliciesRejectsInvalid(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['crossDomainPolicies' => 'open']);
    }

    // -----------------------------------------------------------------------
    // HSTS
    // -----------------------------------------------------------------------

    public function testHstsAcceptsBasicConfiguration(): void
    {
        $config = new Config([
            'hsts' => ['maxAge' => 31536000],
        ]);

        $hsts = $config->getHsts();
        $this->assertIsArray($hsts);
        $this->assertSame(31536000, $hsts['maxAge']);
        $this->assertFalse($hsts['includeSubDomains']);
        $this->assertFalse($hsts['preload']);
    }

    public function testHstsAcceptsFullConfiguration(): void
    {
        $config = new Config([
            'hsts' => [
                'maxAge'            => 63072000,
                'includeSubDomains' => true,
                'preload'           => true,
            ],
        ]);

        $hsts = $config->getHsts();
        $this->assertIsArray($hsts);
        $this->assertSame(63072000, $hsts['maxAge']);
        $this->assertTrue($hsts['includeSubDomains']);
        $this->assertTrue($hsts['preload']);
    }

    public function testHstsDefaultIsFalse(): void
    {
        $config = new Config();
        $this->assertFalse($config->getHsts());
    }

    public function testHstsAcceptsFalse(): void
    {
        $config = new Config(['hsts' => false]);
        $this->assertFalse($config->getHsts());
    }

    public function testHstsRequiresMaxAge(): void
    {
        $this->expectException(ShieldException::class);
        $this->expectExceptionMessageMatches('/maxAge/');
        new Config(['hsts' => []]);
    }

    public function testHstsRejectsNegativeMaxAge(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['hsts' => ['maxAge' => -1]]);
    }

    public function testHstsRejectsStringMaxAge(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['hsts' => ['maxAge' => '31536000']]);
    }

    public function testHstsPreloadRequiresIncludeSubDomains(): void
    {
        $this->expectException(ShieldException::class);
        $this->expectExceptionMessageMatches('/includeSubDomains/');
        new Config([
            'hsts' => [
                'maxAge'  => 31536000,
                'preload' => true,
            ],
        ]);
    }

    public function testHstsPreloadRequiresOneYearMaxAge(): void
    {
        $this->expectException(ShieldException::class);
        $this->expectExceptionMessageMatches('/31536000/');
        new Config([
            'hsts' => [
                'maxAge'            => 3600,
                'includeSubDomains' => true,
                'preload'           => true,
            ],
        ]);
    }

    public function testHstsRejectsNonArrayValue(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['hsts' => 'max-age=31536000']);
    }

    public function testHstsRejectsNonBooleanFlags(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['hsts' => ['maxAge' => 31536000, 'includeSubDomains' => 'false']]);
    }

    public function testHstsRejectsUnknownKeys(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['hsts' => ['maxAge' => 31536000, 'includeSubdomain' => true]]);
    }

    // -----------------------------------------------------------------------
    // CSP
    // -----------------------------------------------------------------------

    public function testCspDefaultIsFalse(): void
    {
        $config = new Config();
        $this->assertFalse($config->getCsp());
        $this->assertFalse($config->isCspReportOnly());
    }

    public function testCspAcceptsDirectives(): void
    {
        $config = new Config([
            'contentSecurityPolicy' => [
                'default-src' => ["'self'"],
                'img-src'     => ["'self'", 'data:'],
            ],
        ]);

        $csp = $config->getCsp();
        $this->assertIsArray($csp);
        $this->assertArrayHasKey('default-src', $csp);
        $this->assertSame(["'self'"], $csp['default-src']);
    }

    public function testCspAcceptsReportOnlyMode(): void
    {
        $config = new Config([
            'contentSecurityPolicy' => [
                'reportOnly'  => true,
                'default-src' => ["'self'"],
            ],
        ]);

        $this->assertTrue($config->isCspReportOnly());
    }

    public function testCspAcceptsBooleanFlagDirectives(): void
    {
        $config = new Config([
            'contentSecurityPolicy' => [
                'upgrade-insecure-requests' => true,
            ],
        ]);

        $csp = $config->getCsp();
        $this->assertIsArray($csp);
        $this->assertTrue($csp['upgrade-insecure-requests']);
    }

    public function testCspAcceptsFalse(): void
    {
        $config = new Config(['contentSecurityPolicy' => false]);
        $this->assertFalse($config->getCsp());
    }

    public function testCspRejectsInvalidDirectiveName(): void
    {
        $this->expectException(ShieldException::class);
        new Config([
            'contentSecurityPolicy' => [
                'INVALID DIRECTIVE' => ["'self'"],
            ],
        ]);
    }

    public function testCspRejectsCrLfInDirectiveName(): void
    {
        $this->expectException(ShieldException::class);
        new Config([
            'contentSecurityPolicy' => [
                "default-src\r\nX-Injected: header" => ["'self'"],
            ],
        ]);
    }

    public function testCspRejectsCrLfInSourceValue(): void
    {
        $this->expectException(ShieldException::class);
        new Config([
            'contentSecurityPolicy' => [
                'default-src' => ["'self'\r\nX-Injected: header"],
            ],
        ]);
    }

    public function testCspRejectsNonArrayValue(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['contentSecurityPolicy' => "default-src 'self'"]);
    }

    public function testCspRejectsNonBooleanReportOnly(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['contentSecurityPolicy' => ['reportOnly' => 'false', 'default-src' => ["'self'"]]]);
    }

    public function testCspRejectsSourcesContainingDirectiveSeparators(): void
    {
        $this->expectException(ShieldException::class);
        new Config([
            'contentSecurityPolicy' => [
                'default-src' => ["'self'; script-src 'unsafe-inline'"],
            ],
        ]);
    }

    public function testCspRejectsNonFlagBooleanDirective(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['contentSecurityPolicy' => ['script-src' => true]]);
    }

    public function testRejectsUnknownTopLevelOption(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['frameOption' => 'DENY']);
    }

    // -----------------------------------------------------------------------
    // Custom headers
    // -----------------------------------------------------------------------

    public function testCustomHeadersAcceptsValidPairs(): void
    {
        $config = new Config([
            'customHeaders' => [
                'X-My-Header'    => 'value',
                'X-Another-One'  => 'other-value',
            ],
        ]);

        $this->assertSame(
            [
                'X-My-Header'   => 'value',
                'X-Another-One' => 'other-value',
            ],
            $config->getCustomHeaders()
        );
    }

    public function testCustomHeadersRejectsCrLfInValue(): void
    {
        $this->expectException(ShieldException::class);
        new Config([
            'customHeaders' => [
                'X-My-Header' => "value\r\nX-Injected: evil",
            ],
        ]);
    }

    public function testCustomHeadersRejectsOtherControlCharacters(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['customHeaders' => ['X-Test' => "value\0"]]);
    }

    public function testCustomHeadersCannotOverrideManagedHeaders(): void
    {
        $this->expectException(ShieldException::class);
        new Config(['customHeaders' => ['x-frame-options' => 'ALLOWALL']]);
    }

    public function testCustomHeadersRejectsInvalidHeaderName(): void
    {
        $this->expectException(ShieldException::class);
        new Config([
            'customHeaders' => [
                'X My Header' => 'value', // spaces not allowed
            ],
        ]);
    }

    public function testCustomHeadersRejectsEmptyName(): void
    {
        $this->expectException(ShieldException::class);
        new Config([
            'customHeaders' => [
                '' => 'value',
            ],
        ]);
    }

    public function testCustomHeadersDefaultsToEmpty(): void
    {
        $config = new Config();
        $this->assertSame([], $config->getCustomHeaders());
    }
}
