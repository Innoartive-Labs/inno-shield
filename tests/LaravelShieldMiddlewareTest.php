<?php

declare(strict_types=1);

namespace Innoartive\Shield\Tests;

use Closure;
use Innoartive\Shield\Laravel\ShieldMiddleware;
use Innoartive\Shield\ShieldException;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the Laravel / Lumen middleware adapter.
 *
 * These tests use lightweight stubs to simulate Laravel's request/response
 * objects without requiring illuminate/http to be installed. The stubs
 * replicate the parts of the API that the middleware actually uses:
 *
 *   - $next($request)         — Closure that returns the stub response
 *   - $response->headers->set($name, $value, $replace)
 *
 * This approach confirms that the middleware correctly applies headers using
 * Laravel's response contract. It does NOT prove runtime compatibility with a
 * real Laravel or Lumen application — for that, integration tests with the
 * actual framework are required.
 */
final class LaravelShieldMiddlewareTest extends TestCase
{
    // -----------------------------------------------------------------------
    // Stub infrastructure
    // -----------------------------------------------------------------------

    /**
     * A minimal stub for Laravel's HeaderBag-like $response->headers property.
     */
    private function makeHeaderBag(): object
    {
        return new class () {
            /** @var array<string, string> */
            public array $headers = [];

            public function set(string $name, string $value, bool $replace = true): void
            {
                if ($replace || !isset($this->headers[$name])) {
                    $this->headers[$name] = $value;
                }
            }
        };
    }

    /**
     * A minimal stub for an Illuminate Response.
     */
    private function makeResponse(
        string $body = 'original body',
        int $status = 200,
    ): object {
        $headerBag = $this->makeHeaderBag();

        return new class ($body, $status, $headerBag) {
            public function __construct(
                public readonly string $body,
                public readonly int $status,
                public readonly object $headers,
            ) {}
        };
    }

    /**
     * Build a $next Closure that returns the given response.
     */
    private function makeNext(object $response): Closure
    {
        return static function (object $request) use ($response): object {
            return $response;
        };
    }

    /**
     * A minimal request stub (middleware does not inspect it).
     */
    private function makeRequest(): object
    {
        return new class () {};
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    public function testAppliesDefaultSecurityHeaders(): void
    {
        $middleware = new ShieldMiddleware();
        $response   = $this->makeResponse();
        $next       = $this->makeNext($response);
        $request    = $this->makeRequest();

        /** @var object{headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        $this->assertArrayHasKey('X-Content-Type-Options', $result->headers->headers);
        $this->assertArrayHasKey('X-Frame-Options', $result->headers->headers);
        $this->assertArrayHasKey('Referrer-Policy', $result->headers->headers);
        $this->assertArrayHasKey('X-Permitted-Cross-Domain-Policies', $result->headers->headers);
    }

    public function testDefaultHeaderValues(): void
    {
        $middleware = new ShieldMiddleware();
        $response   = $this->makeResponse();
        $next       = $this->makeNext($response);
        $request    = $this->makeRequest();

        /** @var object{headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        $this->assertSame('nosniff', $result->headers->headers['X-Content-Type-Options']);
        $this->assertSame('SAMEORIGIN', $result->headers->headers['X-Frame-Options']);
        $this->assertSame('strict-origin-when-cross-origin', $result->headers->headers['Referrer-Policy']);
        $this->assertSame('none', $result->headers->headers['X-Permitted-Cross-Domain-Policies']);
    }

    public function testDoesNotApplyHstsByDefault(): void
    {
        $middleware = new ShieldMiddleware();
        $response   = $this->makeResponse();
        $next       = $this->makeNext($response);
        $request    = $this->makeRequest();

        /** @var object{headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        $this->assertArrayNotHasKey('Strict-Transport-Security', $result->headers->headers);
    }

    public function testDoesNotApplyCspByDefault(): void
    {
        $middleware = new ShieldMiddleware();
        $response   = $this->makeResponse();
        $next       = $this->makeNext($response);
        $request    = $this->makeRequest();

        /** @var object{headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        $this->assertArrayNotHasKey('Content-Security-Policy', $result->headers->headers);
        $this->assertArrayNotHasKey('Content-Security-Policy-Report-Only', $result->headers->headers);
    }

    public function testAppliesCustomFrameOptions(): void
    {
        $middleware = new ShieldMiddleware(['frameOptions' => 'DENY']);
        $response   = $this->makeResponse();
        $next       = $this->makeNext($response);
        $request    = $this->makeRequest();

        /** @var object{headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        $this->assertSame('DENY', $result->headers->headers['X-Frame-Options']);
    }

    public function testAppliesHstsWhenConfigured(): void
    {
        $middleware = new ShieldMiddleware([
            'hsts' => ['maxAge' => 31536000, 'includeSubDomains' => true],
        ]);
        $response = $this->makeResponse();
        $next     = $this->makeNext($response);
        $request  = $this->makeRequest();

        /** @var object{headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        $this->assertArrayHasKey('Strict-Transport-Security', $result->headers->headers);
        $this->assertSame(
            'max-age=31536000; includeSubDomains',
            $result->headers->headers['Strict-Transport-Security']
        );
    }

    public function testAppliesCspWhenConfigured(): void
    {
        $middleware = new ShieldMiddleware([
            'contentSecurityPolicy' => ['default-src' => ["'self'"]],
        ]);
        $response = $this->makeResponse();
        $next     = $this->makeNext($response);
        $request  = $this->makeRequest();

        /** @var object{headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        $this->assertArrayHasKey('Content-Security-Policy', $result->headers->headers);
        $this->assertSame("default-src 'self'", $result->headers->headers['Content-Security-Policy']);
    }

    public function testReplacesExistingHeaderByDefault(): void
    {
        $middleware = new ShieldMiddleware(['frameOptions' => 'DENY']);
        $response   = $this->makeResponse();

        // Pre-populate an existing header in the response's header bag.
        $response->headers->headers['X-Frame-Options'] = 'SAMEORIGIN';

        $next    = $this->makeNext($response);
        $request = $this->makeRequest();

        /** @var object{headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        // Shield should replace the existing value.
        $this->assertSame('DENY', $result->headers->headers['X-Frame-Options']);
    }

    public function testPreservesResponseBody(): void
    {
        $middleware = new ShieldMiddleware();
        $response   = $this->makeResponse('hello world');
        $next       = $this->makeNext($response);
        $request    = $this->makeRequest();

        /** @var object{body: string} $result */
        $result = $middleware->handle($request, $next);

        $this->assertSame('hello world', $result->body);
    }

    public function testPreservesResponseStatusCode(): void
    {
        $middleware = new ShieldMiddleware();
        $response   = $this->makeResponse('', 201);
        $next       = $this->makeNext($response);
        $request    = $this->makeRequest();

        /** @var object{status: int} $result */
        $result = $middleware->handle($request, $next);

        $this->assertSame(201, $result->status);
    }

    public function testAppliesCustomHeaders(): void
    {
        $middleware = new ShieldMiddleware([
            'customHeaders' => ['X-App-Id' => 'my-service'],
        ]);
        $response = $this->makeResponse();
        $next     = $this->makeNext($response);
        $request  = $this->makeRequest();

        /** @var object{headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        $this->assertArrayHasKey('X-App-Id', $result->headers->headers);
        $this->assertSame('my-service', $result->headers->headers['X-App-Id']);
    }

    public function testDisablingAHeaderOmitsItFromResponse(): void
    {
        $middleware = new ShieldMiddleware(['frameOptions' => false]);
        $response   = $this->makeResponse();
        $next       = $this->makeNext($response);
        $request    = $this->makeRequest();

        /** @var object{headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        $this->assertArrayNotHasKey('X-Frame-Options', $result->headers->headers);
    }

    public function testConstructorThrowsOnInvalidOption(): void
    {
        $this->expectException(ShieldException::class);
        new ShieldMiddleware(['frameOptions' => 'INVALID_VALUE']);
    }

    public function testCrLfInCustomHeaderThrows(): void
    {
        $this->expectException(ShieldException::class);
        new ShieldMiddleware([
            'customHeaders' => ['X-Evil' => "value\r\nX-Injected: header"],
        ]);
    }

    // -----------------------------------------------------------------------
    // Configuration consistency with core
    // -----------------------------------------------------------------------

    public function testSameOptionsProduceSameHeadersAsCoreShieldHeaders(): void
    {
        $options = [
            'frameOptions'   => 'DENY',
            'referrerPolicy' => 'no-referrer',
        ];

        $coreHeaders = \Innoartive\Shield\Shield::headers($options);

        $middleware = new ShieldMiddleware($options);
        $response   = $this->makeResponse();
        $next       = $this->makeNext($response);
        $request    = $this->makeRequest();

        /** @var object{headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        foreach ($coreHeaders as $name => $value) {
            $this->assertArrayHasKey($name, $result->headers->headers, "Missing header: {$name}");
            $this->assertSame($value, $result->headers->headers[$name], "Mismatch for header: {$name}");
        }
    }

    public function testSupportsResponseExposingHeaderMethod(): void
    {
        $middleware = new ShieldMiddleware(['frameOptions' => 'DENY']);

        $customResponse = new class () {
            /** @var array<string, string> */
            public array $headerMap = [];

            public function header(string $name, string $value, bool $replace = true): static
            {
                if ($replace || !isset($this->headerMap[$name])) {
                    $this->headerMap[$name] = $value;
                }
                return $this;
            }
        };

        $next    = fn (object $req): object => $customResponse;
        $request = $this->makeRequest();

        $result = $middleware->handle($request, $next);

        $this->assertSame('DENY', $result->headerMap['X-Frame-Options']);
        $this->assertSame('nosniff', $result->headerMap['X-Content-Type-Options']);
    }

    public function testSupportsPsr7ResponseWithHeaderMethod(): void
    {
        $middleware = new ShieldMiddleware(['frameOptions' => 'SAMEORIGIN']);

        $psrResponse = new class ([]) {
            public function __construct(
                public readonly array $headers = [],
            ) {}

            public function withHeader(string $name, string $value): static
            {
                $new = $this->headers;
                $new[$name] = $value;
                return new static($new);
            }
        };

        $next    = fn (object $req): object => $psrResponse;
        $request = $this->makeRequest();

        /** @var object{headers: array<string, string>} $result */
        $result = $middleware->handle($request, $next);

        $this->assertSame('SAMEORIGIN', $result->headers['X-Frame-Options']);
        $this->assertSame('nosniff', $result->headers['X-Content-Type-Options']);
    }

    public function testPreservesRedirectResponseAndLocationHeader(): void
    {
        $middleware = new ShieldMiddleware();
        $response   = $this->makeResponse('', 302);
        $response->headers->set('Location', 'https://example.com/login');

        $next    = $this->makeNext($response);
        $request = $this->makeRequest();

        /** @var object{status: int, headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        $this->assertSame(302, $result->status);
        $this->assertSame('https://example.com/login', $result->headers->headers['Location']);
        $this->assertSame('nosniff', $result->headers->headers['X-Content-Type-Options']);
    }

    public function testPreservesExistingUnrelatedHeaders(): void
    {
        $middleware = new ShieldMiddleware();
        $response   = $this->makeResponse('{"status":"ok"}', 200);
        $response->headers->set('Content-Type', 'application/json');
        $response->headers->set('X-Custom-Tracking', 'trace-12345');

        $next    = $this->makeNext($response);
        $request = $this->makeRequest();

        /** @var object{headers: object{headers: array<string, string>}} $result */
        $result = $middleware->handle($request, $next);

        $this->assertSame('application/json', $result->headers->headers['Content-Type']);
        $this->assertSame('trace-12345', $result->headers->headers['X-Custom-Tracking']);
        $this->assertSame('nosniff', $result->headers->headers['X-Content-Type-Options']);
    }
}
