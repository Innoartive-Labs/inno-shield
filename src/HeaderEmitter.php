<?php

declare(strict_types=1);

namespace Innoartive\Shield;

/**
 * HeaderEmitter builds and emits HTTP security headers.
 *
 * This class encapsulates every decision about which `header()` call to make.
 * It is internal to the library.
 */
final class HeaderEmitter
{
    /**
     * Build the complete set of headers to emit from a resolved Config.
     *
     * Returns an associative array of header-name => header-value pairs.
     * The caller is responsible for emitting them (via PHP's header() or into
     * a PSR-7 response object).
     *
     * @return array<string, string>
     */
    public static function build(Config $config): array
    {
        $headers = [];

        // X-Content-Type-Options
        if ($config->getContentTypeOptions() !== false) {
            $headers['X-Content-Type-Options'] = $config->getContentTypeOptions();
        }

        // X-Frame-Options
        if ($config->getFrameOptions() !== false) {
            $headers['X-Frame-Options'] = $config->getFrameOptions();
        }

        // Referrer-Policy
        if ($config->getReferrerPolicy() !== false) {
            $headers['Referrer-Policy'] = $config->getReferrerPolicy();
        }

        // X-Permitted-Cross-Domain-Policies
        if ($config->getCrossDomainPolicies() !== false) {
            $headers['X-Permitted-Cross-Domain-Policies'] = $config->getCrossDomainPolicies();
        }

        // Strict-Transport-Security
        $hsts = $config->getHsts();
        if ($hsts !== false) {
            $headers['Strict-Transport-Security'] = self::buildHstsValue($hsts);
        }

        // Content-Security-Policy / Content-Security-Policy-Report-Only
        $csp = $config->getCsp();
        if ($csp !== false) {
            $headerName = $config->isCspReportOnly()
                ? 'Content-Security-Policy-Report-Only'
                : 'Content-Security-Policy';
            $headers[$headerName] = self::buildCspValue($csp);
        }

        // Custom headers cannot replace Shield-managed headers.
        foreach ($config->getCustomHeaders() as $name => $value) {
            $headers[$name] = $value;
        }

        return $headers;
    }

    /**
     * Emit headers directly via PHP's global header() function.
     *
     * @param array<string, string> $headers
     * @throws ShieldException If headers have already been sent.
     */
    public static function emit(array $headers): void
    {
        if (headers_sent($file, $line)) {
            throw new ShieldException(
                "Cannot apply security headers: output has already been sent"
                . ($file ? " (output started in {$file}:{$line})" : '') . '. '
                . 'Call Shield::protect() before any output is produced.'
            );
        }

        foreach ($headers as $name => $value) {
            header("{$name}: {$value}", true);
        }
    }

    // -----------------------------------------------------------------------
    // Private builders
    // -----------------------------------------------------------------------

    /**
     * @param array{maxAge: int, includeSubDomains: bool, preload: bool} $hsts
     */
    private static function buildHstsValue(array $hsts): string
    {
        $value = 'max-age=' . $hsts['maxAge'];

        if ($hsts['includeSubDomains']) {
            $value .= '; includeSubDomains';
        }

        if ($hsts['preload']) {
            $value .= '; preload';
        }

        return $value;
    }

    /**
     * @param array<string, list<string>|bool> $directives
     */
    private static function buildCspValue(array $directives): string
    {
        $parts = [];

        foreach ($directives as $directive => $sources) {
            if ($sources === false) {
                // Explicitly disabled directive — skip it
                continue;
            }

            if ($sources === true) {
                // Boolean flag directive (no value, e.g. upgrade-insecure-requests)
                $parts[] = $directive;
                continue;
            }

            /** @var list<string> $sources */
            $parts[] = $directive . (count($sources) > 0 ? ' ' . implode(' ', $sources) : '');
        }

        return implode('; ', $parts);
    }
}
