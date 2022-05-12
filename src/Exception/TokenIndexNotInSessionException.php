<?php
declare(strict_types=1);

namespace ParagonIE\AntiCSRF\Exception;

/**
 * Class TokenIndexNotInSessionException
 *
 * @package ParagonIE\AntiCSRF
 */
class TokenIndexNotInSessionException extends AntiCSRFException
{
    const CODE_NATIVE = 1;
    const CODE_CONSTRUCTOR = 2;

    public static function fromNative(string $sessionIndex): self
    {
        return new self(
            \sprintf('Token not found in native $_SESSION at index "%s"', $sessionIndex),
            self::CODE_NATIVE
        );
    }

    public static function fromConstructor(string $sessionIndex): self
    {
        return new self(
            \sprintf('Token not found in constructor session at index "%s"', $sessionIndex),
            self::CODE_CONSTRUCTOR
        );
    }
}
