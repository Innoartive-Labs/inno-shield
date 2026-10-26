<?php

declare(strict_types=1);

namespace Innoartive\Shield\Tests;

use Innoartive\Shield\Config;
use Innoartive\Shield\HeaderEmitter;
use Innoartive\Shield\ShieldMiddleware;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the optional PSR-15 middleware adapter.
 *
 * These tests use lightweight stubs for PSR-7 request/response and PSR-15
 * handler objects so that the test suite can run without requiring the actual
 * PSR packages to be installed.
 */
final class ShieldMiddlewareTest extends TestCase
{
    // -----------------------------------------------------------------------
    // Stub infrastructure
    // -----------------------------------------------------------------------

    /**
     * Returns a minimal request stub. The middleware only passes it through.
     */
    private function makeRequest(): object
    {
        return new class () {
            // No methods needed — the middleware forwards it unchanged.
        };
    }

    /**
     * Returns a handler stub that wraps a response stub.
     */
    private function makeHandler(object $response): object
    {
        return new class ($response) {
            public function __construct(private readonly object $response) {}

            public function handle(object $request): object
            {
                return $this->response;
            }
        };
    }

    /**
     * Returns a minimal response stub that accumulates withHeader() calls.
     */
    private function makeResponse(): object
    {
        return new class () {
            /** @var array<string, string> */
            public array $headers = [];
            public string $body   = 'original body';
            public int    $status = 200;

            public function withHeader(string $name, string $value): static
            {
                $clone          = clone $this;
                $clone->headers = [...$this->headers, $name => $value];
                return $clone;
            }
        };
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    public function testMiddlewareAppliesDefaultSecurityHeaders(): void
    {
        $middleware = new ShieldMiddleware();
        $response   = $this->makeResponse();
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        /** @var object{headers: array<string, string>} $result */
        $result = $middleware->process($request, $handler);

        $this->assertArrayHasKey('X-Content-Type-Options', $result->headers);
        $this->assertArrayHasKey('X-Frame-Options', $result->headers);
        $this->assertArrayHasKey('Referrer-Policy', $result->headers);
        $this->assertArrayHasKey('X-Permitted-Cross-Domain-Policies', $result->headers);
    }

    public function testMiddlewarePreservesResponseBody(): void
    {
        $middleware = new ShieldMiddleware();
        $response   = $this->makeResponse();
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        /** @var object{body: string} $result */
        $result = $middleware->process($request, $handler);

        $this->assertSame('original body', $result->body);
    }

    public function testMiddlewarePreservesResponseStatus(): void
    {
        $middleware = new ShieldMiddleware();
        $response   = $this->makeResponse();
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        /** @var object{status: int} $result */
        $result = $middleware->process($request, $handler);

        $this->assertSame(200, $result->status);
    }

    public function testMiddlewareReplacesExistingSecurityHeaderWithConfiguredValue(): void
    {
        // Simulates a response that already has X-Frame-Options set.
        $response = new class () {
            public array $headers = ['X-Frame-Options' => 'ALLOWALL'];
            public string $body   = '';

            public function withHeader(string $name, string $value): static
            {
                $clone                  = clone $this;
                $clone->headers[$name]  = $value;
                return $clone;
            }
        };

        $middleware = new ShieldMiddleware(['frameOptions' => 'DENY']);
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        /** @var object{headers: array<string, string>} $result */
        $result = $middleware->process($request, $handler);

        $this->assertSame('DENY', $result->headers['X-Frame-Options']);
    }

    public function testMiddlewareDoesNotIncludeHstsByDefault(): void
    {
        $middleware = new ShieldMiddleware();
        $response   = $this->makeResponse();
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        /** @var object{headers: array<string, string>} $result */
        $result = $middleware->process($request, $handler);

        $this->assertArrayNotHasKey('Strict-Transport-Security', $result->headers);
    }

    public function testMiddlewareAppliesHstsWhenConfigured(): void
    {
        $middleware = new ShieldMiddleware([
            'hsts' => ['maxAge' => 31536000, 'includeSubDomains' => true],
        ]);
        $response = $this->makeResponse();
        $handler  = $this->makeHandler($response);
        $request  = $this->makeRequest();

        /** @var object{headers: array<string, string>} $result */
        $result = $middleware->process($request, $handler);

        $this->assertArrayHasKey('Strict-Transport-Security', $result->headers);
        $this->assertSame(
            'max-age=31536000; includeSubDomains',
            $result->headers['Strict-Transport-Security']
        );
    }

    public function testMiddlewareAppliesCspWhenConfigured(): void
    {
        $middleware = new ShieldMiddleware([
            'contentSecurityPolicy' => [
                'default-src' => ["'self'"],
            ],
        ]);
        $response = $this->makeResponse();
        $handler  = $this->makeHandler($response);
        $request  = $this->makeRequest();

        /** @var object{headers: array<string, string>} $result */
        $result = $middleware->process($request, $handler);

        $this->assertArrayHasKey('Content-Security-Policy', $result->headers);
        $this->assertSame("default-src 'self'", $result->headers['Content-Security-Policy']);
    }

    public function testMiddlewareAppliesCustomHeaders(): void
    {
        $middleware = new ShieldMiddleware([
            'customHeaders' => ['X-App-Id' => 'my-service'],
        ]);
        $response = $this->makeResponse();
        $handler  = $this->makeHandler($response);
        $request  = $this->makeRequest();

        /** @var object{headers: array<string, string>} $result */
        $result = $middleware->process($request, $handler);

        $this->assertArrayHasKey('X-App-Id', $result->headers);
        $this->assertSame('my-service', $result->headers['X-App-Id']);
    }
}
