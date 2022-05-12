<?php
declare(strict_types=1);

namespace ParagonIE\AntiCSRF\Exception;

/**
 * Class FormLockException
 *
 * @package ParagonIE\AntiCSRF
 */
class FormLockException extends AntiCSRFException
{
    public static function create(string $lockTo): self
    {
        return new self(
            \sprintf('Form action "%s" did not match the stored value', $lockTo)
        );
    }
}
