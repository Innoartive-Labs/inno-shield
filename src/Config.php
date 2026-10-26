<?php

declare(strict_types=1);

namespace Innoartive\Shield;

/**
 * Resolves and validates Shield options.
 */
final class Config
{
    // -----------------------------------------------------------------------
    // Allowed values for string-enum options
    // -----------------------------------------------------------------------

    private const FRAME_OPTIONS_ALLOWED = ['DENY', 'SAMEORIGIN'];

    private const REFERRER_POLICY_ALLOWED = [
        'no-referrer',
        'no-referrer-when-downgrade',
        'origin',
        'origin-when-cross-origin',
        'same-origin',
        'strict-origin',
        'strict-origin-when-cross-origin',
        'unsafe-url',
        '',
    ];

    private const CROSS_DOMAIN_POLICY_ALLOWED = [
        'none',
        'master-only',
        'by-content-type',
        'all',
    ];

    private const CONTENT_TYPE_OPTIONS_ALLOWED = ['nosniff'];

    private const OPTION_KEYS = [
        'contentTypeOptions',
        'frameOptions',
        'referrerPolicy',
        'crossDomainPolicies',
        'hsts',
        'contentSecurityPolicy',
        'customHeaders',
    ];

    private const HSTS_KEYS = ['maxAge', 'includeSubDomains', 'preload'];

    private const CSP_FLAG_DIRECTIVES = [
        'block-all-mixed-content',
        'upgrade-insecure-requests',
    ];

    private const MANAGED_HEADER_NAMES = [
        'content-security-policy',
        'content-security-policy-report-only',
        'strict-transport-security',
        'x-content-type-options',
        'x-frame-options',
        'referrer-policy',
        'x-permitted-cross-domain-policies',
    ];

    // -----------------------------------------------------------------------
    // Library defaults (safe for any general-purpose PHP application)
    // -----------------------------------------------------------------------

    /**
     * Returns the default option set.
     *
     * CSP and HSTS are disabled by default to avoid breaking existing
     * applications on first installation.
     *
     * @return array<string, mixed>
     */
    public static function defaults(): array
    {
        return [
            // Core headers — always applied unless explicitly set to false
            'contentTypeOptions'         => 'nosniff',
            'frameOptions'               => 'SAMEORIGIN',
            'referrerPolicy'             => 'strict-origin-when-cross-origin',
            'crossDomainPolicies'        => 'none',

            // HSTS — opt-in only; never enabled by default
            'hsts'                       => false,

            // Content Security Policy — opt-in only
            'contentSecurityPolicy'      => false,

            // Custom headers — empty by default
            'customHeaders'              => [],
        ];
    }

    // -----------------------------------------------------------------------
    // Resolved state
    // -----------------------------------------------------------------------

    private readonly string|false $contentTypeOptions;
    private readonly string|false $frameOptions;
    private readonly string|false $referrerPolicy;
    private readonly string|false $crossDomainPolicies;

    /** @var array{maxAge: int, includeSubDomains: bool, preload: bool}|false */
    private readonly array|false $hsts;

    /** @var array<string, list<string>|bool>|false */
    private readonly array|false $csp;

    /** @var bool True when CSP should use report-only mode */
    private readonly bool $cspReportOnly;

    /** @var array<string, string> Validated custom headers to emit */
    private readonly array $customHeaders;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /**
     * @param array<string, mixed> $options Caller-supplied options (partial or full).
     * @throws ShieldException On invalid option values.
     */
    public function __construct(array $options = [])
    {
        $this->assertKnownKeys($options, self::OPTION_KEYS, 'options');
        $merged = array_merge(self::defaults(), $options);

        $this->contentTypeOptions  = $this->resolveContentTypeOptions($merged['contentTypeOptions'] ?? 'nosniff');
        $this->frameOptions        = $this->resolveFrameOptions($merged['frameOptions'] ?? 'SAMEORIGIN');
        $this->referrerPolicy      = $this->resolveReferrerPolicy($merged['referrerPolicy'] ?? 'strict-origin-when-cross-origin');
        $this->crossDomainPolicies = $this->resolveCrossDomainPolicies($merged['crossDomainPolicies'] ?? 'none');
        $this->hsts                = $this->resolveHsts($merged['hsts'] ?? false);

        [$this->csp, $this->cspReportOnly] = $this->resolveCsp($merged['contentSecurityPolicy'] ?? false);

        $this->customHeaders       = $this->resolveCustomHeaders($merged['customHeaders'] ?? []);
    }

    // -----------------------------------------------------------------------
    // Public accessors
    // -----------------------------------------------------------------------

    public function getContentTypeOptions(): string|false
    {
        return $this->contentTypeOptions;
    }

    public function getFrameOptions(): string|false
    {
        return $this->frameOptions;
    }

    public function getReferrerPolicy(): string|false
    {
        return $this->referrerPolicy;
    }

    public function getCrossDomainPolicies(): string|false
    {
        return $this->crossDomainPolicies;
    }

    /**
     * @return array{maxAge: int, includeSubDomains: bool, preload: bool}|false
     */
    public function getHsts(): array|false
    {
        return $this->hsts;
    }

    /**
     * @return array<string, list<string>|bool>|false
     */
    public function getCsp(): array|false
    {
        return $this->csp;
    }

    public function isCspReportOnly(): bool
    {
        return $this->cspReportOnly;
    }

    /**
     * @return array<string, string>
     */
    public function getCustomHeaders(): array
    {
        return $this->customHeaders;
    }

    // -----------------------------------------------------------------------
    // Private resolvers
    // -----------------------------------------------------------------------

    private function resolveContentTypeOptions(mixed $value): string|false
    {
        if ($value === false) {
            return false;
        }

        if (!is_string($value)) {
            throw new ShieldException(
                "Option 'contentTypeOptions' must be a string or false; received " . get_debug_type($value) . '.'
            );
        }

        $upper = strtoupper($value);
        if (!in_array(strtolower($upper), array_map('strtolower', self::CONTENT_TYPE_OPTIONS_ALLOWED), true)) {
            throw new ShieldException(
                "Option 'contentTypeOptions' must be 'nosniff' or false; received '{$value}'."
            );
        }

        return 'nosniff';
    }

    private function resolveFrameOptions(mixed $value): string|false
    {
        if ($value === false) {
            return false;
        }

        if (!is_string($value)) {
            throw new ShieldException(
                "Option 'frameOptions' must be a string or false; received " . get_debug_type($value) . '.'
            );
        }

        $this->assertNoCrlf($value, 'frameOptions');

        $upper = strtoupper(trim($value));
        if (!in_array($upper, self::FRAME_OPTIONS_ALLOWED, true)) {
            $allowed = implode(', ', self::FRAME_OPTIONS_ALLOWED);
            throw new ShieldException(
                "Option 'frameOptions' must be one of [{$allowed}] or false; received '{$value}'."
            );
        }

        return $upper;
    }

    private function resolveReferrerPolicy(mixed $value): string|false
    {
        if ($value === false) {
            return false;
        }

        if (!is_string($value)) {
            throw new ShieldException(
                "Option 'referrerPolicy' must be a string or false; received " . get_debug_type($value) . '.'
            );
        }

        $this->assertNoCrlf($value, 'referrerPolicy');

        $lower = strtolower(trim($value));
        if (!in_array($lower, self::REFERRER_POLICY_ALLOWED, true)) {
            $allowed = implode(', ', array_filter(self::REFERRER_POLICY_ALLOWED, fn (string $s) => $s !== ''));
            throw new ShieldException(
                "Option 'referrerPolicy' received an unrecognised value '{$value}'. "
                . "Allowed values: [{$allowed}]."
            );
        }

        return $lower;
    }

    private function resolveCrossDomainPolicies(mixed $value): string|false
    {
        if ($value === false) {
            return false;
        }

        if (!is_string($value)) {
            throw new ShieldException(
                "Option 'crossDomainPolicies' must be a string or false; received " . get_debug_type($value) . '.'
            );
        }

        $this->assertNoCrlf($value, 'crossDomainPolicies');

        $lower = strtolower(trim($value));
        if (!in_array($lower, self::CROSS_DOMAIN_POLICY_ALLOWED, true)) {
            $allowed = implode(', ', self::CROSS_DOMAIN_POLICY_ALLOWED);
            throw new ShieldException(
                "Option 'crossDomainPolicies' must be one of [{$allowed}] or false; received '{$value}'."
            );
        }

        return $lower;
    }

    /**
     * @return array{maxAge: int, includeSubDomains: bool, preload: bool}|false
     */
    private function resolveHsts(mixed $value): array|false
    {
        if ($value === false) {
            return false;
        }

        if (!is_array($value)) {
            throw new ShieldException(
                "Option 'hsts' must be an array of HSTS directives or false. "
                . "Example: ['maxAge' => 31536000, 'includeSubDomains' => true]."
            );
        }

        $this->assertKnownKeys($value, self::HSTS_KEYS, 'hsts');

        if (!isset($value['maxAge'])) {
            throw new ShieldException(
                "Option 'hsts' requires a 'maxAge' key specifying the max-age in seconds (integer >= 0)."
            );
        }

        $maxAge = $value['maxAge'];
        if (!is_int($maxAge) || $maxAge < 0) {
            throw new ShieldException(
                "Option 'hsts.maxAge' must be a non-negative integer; received " . var_export($maxAge, true) . '.'
            );
        }

        $includeSubDomains = $this->resolveBoolean($value['includeSubDomains'] ?? false, 'hsts.includeSubDomains');
        $preload = $this->resolveBoolean($value['preload'] ?? false, 'hsts.preload');

        if ($preload && !$includeSubDomains) {
            throw new ShieldException(
                "Option 'hsts.preload' requires 'includeSubDomains' to also be true. "
                . "HSTS preload lists require includeSubDomains to be present."
            );
        }

        if ($preload && $maxAge < 31536000) {
            throw new ShieldException(
                "Option 'hsts.preload' requires 'maxAge' to be at least 31536000 (one year). "
                . "Received: {$maxAge}."
            );
        }

        return [
            'maxAge'            => $maxAge,
            'includeSubDomains' => $includeSubDomains,
            'preload'           => $preload,
        ];
    }

    /**
     * @return array{0: array<string, list<string>|bool>|false, 1: bool}
     */
    private function resolveCsp(mixed $value): array
    {
        if ($value === false) {
            return [false, false];
        }

        if (!is_array($value)) {
            throw new ShieldException(
                "Option 'contentSecurityPolicy' must be an associative array of CSP directives or false."
            );
        }

        $reportOnly = $this->resolveBoolean($value['reportOnly'] ?? false, 'contentSecurityPolicy.reportOnly');

        // Strip meta-keys before processing directives
        $directives = $value;
        unset($directives['reportOnly']);

        $resolved = [];
        foreach ($directives as $directive => $sources) {
            if (!is_string($directive)) {
                throw new ShieldException(
                    "CSP directive keys must be strings; received " . get_debug_type($directive) . '.'
                );
            }

            $this->assertNoCrlf($directive, "contentSecurityPolicy[{$directive}]");

            // Normalise directive name to kebab-case
            $directive = strtolower(trim($directive));

            if (!$this->isValidCspDirectiveName($directive)) {
                throw new ShieldException(
                    "'{$directive}' is not a valid CSP directive name. "
                    . "Directive names must match [a-z][a-z0-9-]*."
                );
            }

            if ($sources === true || $sources === false) {
                if ($sources === true && !in_array($directive, self::CSP_FLAG_DIRECTIVES, true)) {
                    throw new ShieldException(
                        "CSP directive '{$directive}' must be an array of source strings or false."
                    );
                }

                $resolved[$directive] = $sources;
                continue;
            }

            if (!is_array($sources)) {
                throw new ShieldException(
                    "CSP directive '{$directive}' must be an array of source strings or a boolean; "
                    . "received " . get_debug_type($sources) . '.'
                );
            }

            $resolvedSources = [];
            foreach ($sources as $source) {
                if (!is_string($source)) {
                    throw new ShieldException(
                        "Each source in CSP directive '{$directive}' must be a string; "
                        . "received " . get_debug_type($source) . '.'
                    );
                }
                $this->assertValidCspSource($source, $directive);
                $resolvedSources[] = $source;
            }

            $resolved[$directive] = $resolvedSources;
        }

        return [$resolved, $reportOnly];
    }

    /**
     * @param array<string, string>|mixed $value
     * @return array<string, string>
     */
    private function resolveCustomHeaders(mixed $value): array
    {
        if (!is_array($value)) {
            throw new ShieldException(
                "Option 'customHeaders' must be an associative array of header name => value pairs."
            );
        }

        $validated = [];
        foreach ($value as $name => $headerValue) {
            if (!is_string($name) || !is_string($headerValue)) {
                throw new ShieldException(
                    "Option 'customHeaders' must contain string keys and string values."
                );
            }

            $this->assertValidHeaderName($name);
            $this->assertValidHeaderValue($headerValue, "customHeaders[{$name}]");

            if (in_array(strtolower($name), self::MANAGED_HEADER_NAMES, true)) {
                throw new ShieldException(
                    "Custom header '{$name}' conflicts with a Shield-managed header. Use its dedicated option instead."
                );
            }

            $validated[$name] = $headerValue;
        }

        return $validated;
    }

    // -----------------------------------------------------------------------
    // Guards
    // -----------------------------------------------------------------------

    /** Reject CR/LF to prevent header injection. */
    private function assertNoCrlf(string $value, string $optionPath): void
    {
        if (str_contains($value, "\r") || str_contains($value, "\n")) {
            throw new ShieldException(
                "Option '{$optionPath}' contains a carriage return or line feed character, "
                . "which is not permitted in HTTP header values."
            );
        }
    }

    /** Reject controls that cannot appear in HTTP field values. */
    private function assertValidHeaderValue(string $value, string $optionPath): void
    {
        if (preg_match('/[\x00-\x08\x0A-\x1F\x7F]/', $value)) {
            throw new ShieldException("Option '{$optionPath}' contains an unsafe HTTP header character.");
        }
    }

    /** Reject CSP token separators inside a source expression. */
    private function assertValidCspSource(string $source, string $directive): void
    {
        $this->assertValidHeaderValue($source, "contentSecurityPolicy[{$directive}] source");

        if ($source === '' || preg_match('/[\s;,]/', $source)) {
            throw new ShieldException(
                "CSP source values for '{$directive}' must be a single source expression."
            );
        }
    }

    /** @param list<string> $allowedKeys */
    private function assertKnownKeys(array $values, array $allowedKeys, string $optionPath): void
    {
        foreach ($values as $key => $_) {
            if (!is_string($key) || !in_array($key, $allowedKeys, true)) {
                $displayKey = is_string($key) ? $key : (string) $key;
                throw new ShieldException("Unknown option '{$optionPath}.{$displayKey}'.");
            }
        }
    }

    private function resolveBoolean(mixed $value, string $optionPath): bool
    {
        if (!is_bool($value)) {
            throw new ShieldException(
                "Option '{$optionPath}' must be a boolean; received " . get_debug_type($value) . '.'
            );
        }

        return $value;
    }

    /**
     * Validate an HTTP header name per RFC 7230 token rules.
     *
     * @throws ShieldException
     */
    private function assertValidHeaderName(string $name): void
    {
        if ($name === '') {
            throw new ShieldException(
                "Custom header name must not be empty."
            );
        }

        // RFC 7230 token: printable ASCII excluding delimiters
        if (!preg_match('/^[!#$%&\'*+\-.0-9A-Z^_`a-z|~]+$/', $name)) {
            throw new ShieldException(
                "Custom header name '{$name}' contains characters that are not allowed in HTTP header names."
            );
        }

        $this->assertNoCrlf($name, "customHeaders key '{$name}'");
    }

    /**
     * Validate a CSP directive name.
     * Directive names must consist of lowercase letters, digits, and hyphens.
     */
    private function isValidCspDirectiveName(string $name): bool
    {
        return (bool) preg_match('/^[a-z][a-z0-9-]*$/', $name);
    }
}
