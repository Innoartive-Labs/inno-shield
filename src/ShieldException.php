<?php

declare(strict_types=1);

namespace Innoartive\Shield;

/**
 * ShieldException is thrown when Shield encounters invalid configuration,
 * unsafe header values, or an unrecoverable runtime condition.
 *
 * It is intentionally not a fatal error so calling code can catch and handle
 * it appropriately (e.g., log and abort the request gracefully).
 */
final class ShieldException extends \RuntimeException {}
