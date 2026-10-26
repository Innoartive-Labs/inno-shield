<?php

declare(strict_types=1);

namespace Innoartive\Shield\Tests;

use Innoartive\Shield\ShieldPsr15Middleware;
use Innoartive\Shield\ShieldException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Tests for ShieldPsr15Middleware — formal PSR-15 compliance.
 *
 * These tests require psr/http-server-middleware, psr/http-server-handler,
 * and psr/http-message, which are in require-dev.
 * They use lightweight in-test stubs that properly implement PSR interfaces.
 */
final class ShieldPsr15MiddlewareTest extends TestCase
{
    // -----------------------------------------------------------------------
    // PSR-compliant stubs
    // -----------------------------------------------------------------------

    /**
     * A minimal PSR-7 stream stub.
     */
    private function makeStream(): StreamInterface
    {
        return new class () implements StreamInterface {
            public function __toString(): string { return 'original body'; }
            public function close(): void {}
            public function detach() { return null; }
            public function getSize(): ?int { return 13; }
            public function tell(): int { return 0; }
            public function eof(): bool { return true; }
            public function isSeekable(): bool { return false; }
            public function seek(int $offset, int $whence = SEEK_SET): void {}
            public function rewind(): void {}
            public function isWritable(): bool { return false; }
            public function write(string $string): int { return 0; }
            public function isReadable(): bool { return true; }
            public function read(int $length): string { return 'original body'; }
            public function getContents(): string { return 'original body'; }
            public function getMetadata(?string $key = null): mixed { return null; }
        };
    }

    /**
     * A minimal PSR-7 response stub with real interface implementation.
     *
     * @param array<string, list<string>> $initialHeaders
     */
    private function makeResponse(array $initialHeaders = []): ResponseInterface
    {
        return new class ($initialHeaders, $this->makeStream()) implements ResponseInterface {
            /** @var array<string, list<string>> */
            private array $headers;

            public function __construct(
                array $headers,
                private readonly StreamInterface $stream,
                private readonly int $statusCode = 200,
                private readonly string $reasonPhrase = 'OK',
                private readonly string $protocolVersion = '1.1',
            ) {
                $this->headers = $headers;
            }

            public function getStatusCode(): int { return $this->statusCode; }
            public function getReasonPhrase(): string { return $this->reasonPhrase; }
            public function getProtocolVersion(): string { return $this->protocolVersion; }
            public function getBody(): StreamInterface { return $this->stream; }

            public function withStatus(int $code, string $reasonPhrase = ''): static
            {
                return new static(
                    $this->headers,
                    $this->stream,
                    $code,
                    $reasonPhrase !== '' ? $reasonPhrase : $this->reasonPhrase,
                    $this->protocolVersion,
                );
            }

            public function withProtocolVersion(string $version): static { return clone $this; }
            public function withBody(StreamInterface $body): static { return clone $this; }

            public function getHeaders(): array { return $this->headers; }

            public function hasHeader(string $name): bool
            {
                return isset($this->headers[strtolower($name)])
                    || isset($this->headers[$name]);
            }

            public function getHeader(string $name): array
            {
                return $this->headers[$name] ?? $this->headers[strtolower($name)] ?? [];
            }

            public function getHeaderLine(string $name): string
            {
                return implode(', ', $this->getHeader($name));
            }

            public function withHeader(string $name, mixed $value): static
            {
                $clone = clone $this;
                $clone->headers[$name] = is_array($value) ? $value : [$value];
                return $clone;
            }

            public function withAddedHeader(string $name, mixed $value): static
            {
                $clone = clone $this;
                $existing = $clone->headers[$name] ?? [];
                $clone->headers[$name] = array_merge($existing, is_array($value) ? $value : [$value]);
                return $clone;
            }

            public function withoutHeader(string $name): static
            {
                $clone = clone $this;
                unset($clone->headers[$name]);
                return $clone;
            }
        };
    }

    /**
     * A minimal PSR-7 server request stub.
     */
    private function makeRequest(): ServerRequestInterface
    {
        return new class () implements ServerRequestInterface {
            public function getServerParams(): array { return []; }
            public function getCookieParams(): array { return []; }
            public function withCookieParams(array $cookies): static { return clone $this; }
            public function getQueryParams(): array { return []; }
            public function withQueryParams(array $query): static { return clone $this; }
            public function getUploadedFiles(): array { return []; }
            public function withUploadedFiles(array $uploadedFiles): static { return clone $this; }
            public function getParsedBody(): object|array|null { return null; }
            public function withParsedBody($data): static { return clone $this; }
            public function getAttributes(): array { return []; }
            public function getAttribute(string $name, mixed $default = null): mixed { return $default; }
            public function withAttribute(string $name, mixed $value): static { return clone $this; }
            public function withoutAttribute(string $name): static { return clone $this; }
            public function getRequestTarget(): string { return '/'; }
            public function withRequestTarget(string $requestTarget): static { return clone $this; }
            public function getMethod(): string { return 'GET'; }
            public function withMethod(string $method): static { return clone $this; }
            public function getUri(): \Psr\Http\Message\UriInterface { throw new \LogicException('Not needed'); }
            public function withUri(\Psr\Http\Message\UriInterface $uri, bool $preserveHost = false): static { return clone $this; }
            public function getProtocolVersion(): string { return '1.1'; }
            public function withProtocolVersion(string $version): static { return clone $this; }
            public function getHeaders(): array { return []; }
            public function hasHeader(string $name): bool { return false; }
            public function getHeader(string $name): array { return []; }
            public function getHeaderLine(string $name): string { return ''; }
            public function withHeader(string $name, mixed $value): static { return clone $this; }
            public function withAddedHeader(string $name, mixed $value): static { return clone $this; }
            public function withoutHeader(string $name): static { return clone $this; }
            public function getBody(): StreamInterface { throw new \LogicException('Not needed'); }
            public function withBody(StreamInterface $body): static { return clone $this; }
        };
    }

    /**
     * A minimal PSR-15 handler stub.
     */
    private function makeHandler(ResponseInterface $response): RequestHandlerInterface
    {
        return new class ($response) implements RequestHandlerInterface {
            public function __construct(private readonly ResponseInterface $response) {}

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->response;
            }
        };
    }

    // -----------------------------------------------------------------------
    // Interface compliance
    // -----------------------------------------------------------------------

    public function testImplementsMiddlewareInterface(): void
    {
        $middleware = new ShieldPsr15Middleware();
        $this->assertInstanceOf(MiddlewareInterface::class, $middleware);
    }

    // -----------------------------------------------------------------------
    // Header application
    // -----------------------------------------------------------------------

    public function testAppliesDefaultSecurityHeaders(): void
    {
        $middleware = new ShieldPsr15Middleware();
        $response   = $this->makeResponse();
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        $result = $middleware->process($request, $handler);

        $this->assertTrue($result->hasHeader('X-Content-Type-Options'));
        $this->assertTrue($result->hasHeader('X-Frame-Options'));
        $this->assertTrue($result->hasHeader('Referrer-Policy'));
        $this->assertTrue($result->hasHeader('X-Permitted-Cross-Domain-Policies'));
    }

    public function testDefaultHeaderValues(): void
    {
        $middleware = new ShieldPsr15Middleware();
        $response   = $this->makeResponse();
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        $result = $middleware->process($request, $handler);

        $this->assertSame('nosniff', $result->getHeaderLine('X-Content-Type-Options'));
        $this->assertSame('SAMEORIGIN', $result->getHeaderLine('X-Frame-Options'));
        $this->assertSame('strict-origin-when-cross-origin', $result->getHeaderLine('Referrer-Policy'));
        $this->assertSame('none', $result->getHeaderLine('X-Permitted-Cross-Domain-Policies'));
    }

    public function testDoesNotApplyHstsByDefault(): void
    {
        $middleware = new ShieldPsr15Middleware();
        $response   = $this->makeResponse();
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        $result = $middleware->process($request, $handler);

        $this->assertFalse($result->hasHeader('Strict-Transport-Security'));
    }

    public function testDoesNotApplyCspByDefault(): void
    {
        $middleware = new ShieldPsr15Middleware();
        $response   = $this->makeResponse();
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        $result = $middleware->process($request, $handler);

        $this->assertFalse($result->hasHeader('Content-Security-Policy'));
        $this->assertFalse($result->hasHeader('Content-Security-Policy-Report-Only'));
    }

    public function testAppliesHstsWhenConfigured(): void
    {
        $middleware = new ShieldPsr15Middleware([
            'hsts' => ['maxAge' => 31536000, 'includeSubDomains' => true],
        ]);
        $response = $this->makeResponse();
        $handler  = $this->makeHandler($response);
        $request  = $this->makeRequest();

        $result = $middleware->process($request, $handler);

        $this->assertTrue($result->hasHeader('Strict-Transport-Security'));
        $this->assertSame('max-age=31536000; includeSubDomains', $result->getHeaderLine('Strict-Transport-Security'));
    }

    public function testAppliesCspWhenConfigured(): void
    {
        $middleware = new ShieldPsr15Middleware([
            'contentSecurityPolicy' => ['default-src' => ["'self'"]],
        ]);
        $response = $this->makeResponse();
        $handler  = $this->makeHandler($response);
        $request  = $this->makeRequest();

        $result = $middleware->process($request, $handler);

        $this->assertTrue($result->hasHeader('Content-Security-Policy'));
        $this->assertSame("default-src 'self'", $result->getHeaderLine('Content-Security-Policy'));
    }

    // -----------------------------------------------------------------------
    // Response preservation
    // -----------------------------------------------------------------------

    public function testPreservesResponseStatusCode(): void
    {
        $middleware = new ShieldPsr15Middleware();
        $response   = $this->makeResponse();
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        $result = $middleware->process($request, $handler);

        $this->assertSame(200, $result->getStatusCode());
    }

    public function testPreservesResponseBody(): void
    {
        $middleware = new ShieldPsr15Middleware();
        $response   = $this->makeResponse();
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        $result = $middleware->process($request, $handler);

        $this->assertSame('original body', (string) $result->getBody());
    }

    public function testReplacesExistingHeaderWithConfiguredValue(): void
    {
        $middleware = new ShieldPsr15Middleware(['frameOptions' => 'DENY']);
        $response   = $this->makeResponse(['X-Frame-Options' => ['SAMEORIGIN']]);
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        $result = $middleware->process($request, $handler);

        $this->assertSame('DENY', $result->getHeaderLine('X-Frame-Options'));
    }

    public function testPreservesRedirectAndLocationHeader(): void
    {
        $middleware = new ShieldPsr15Middleware();
        $response   = $this->makeResponse(['Location' => ['https://example.com/auth']])
            ->withStatus(302, 'Found');
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        $result = $middleware->process($request, $handler);

        $this->assertSame(302, $result->getStatusCode());
        $this->assertSame('https://example.com/auth', $result->getHeaderLine('Location'));
        $this->assertSame('nosniff', $result->getHeaderLine('X-Content-Type-Options'));
    }

    public function testPreservesUnrelatedHeaders(): void
    {
        $middleware = new ShieldPsr15Middleware();
        $response   = $this->makeResponse(['X-Correlation-ID' => ['corr-abc-123']]);
        $handler    = $this->makeHandler($response);
        $request    = $this->makeRequest();

        $result = $middleware->process($request, $handler);

        $this->assertSame('corr-abc-123', $result->getHeaderLine('X-Correlation-ID'));
        $this->assertSame('nosniff', $result->getHeaderLine('X-Content-Type-Options'));
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    public function testConstructorThrowsOnInvalidOption(): void
    {
        $this->expectException(ShieldException::class);
        new ShieldPsr15Middleware(['frameOptions' => 'ALLOWALL']);
    }
}
