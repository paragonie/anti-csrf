<?php
declare(strict_types=1);

namespace ParagonIE\AntiCSRF\Exception;

/**
 * Class TokenHashException
 *
 * @package ParagonIE\AntiCSRF
 */
class TokenHashException extends AntiCSRFException
{
    public static function create(string $token): self
    {
        return new self(
            \sprintf('Token "%s" did not match the stored value', $token)
        );
    }
}
