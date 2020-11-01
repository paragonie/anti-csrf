<?php
declare(strict_types=1);

namespace ParagonIE\AntiCSRF\Exception;

/**
 * Class TokenNotInSessionException
 *
 * @package ParagonIE\AntiCSRF
 */
class TokenNotInSessionException extends AntiCSRFException
{
    public static function create(string $formIndex): self
    {
        return new self(
            \sprintf('Token with index "%s" not found in session', $formIndex),
        );
    }
}
