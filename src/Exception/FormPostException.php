<?php
declare(strict_types=1);

namespace ParagonIE\AntiCSRF\Exception;

/**
 * Class TokenNotInSessionException
 *
 * @package ParagonIE\AntiCSRF
 */
class FormPostException extends AntiCSRFException
{
    const CODE_MISSING_INDEX = 1;
    const CODE_MISSING_TOKEN = 2;
    const CODE_TYPE_INDEX = 3;
    const CODE_TYPE_TOKEN = 4;

    public static function missingIndex(string $formFieldName): self
    {
        return new self(
            \sprintf('Missing index form post with name "%s"', $formFieldName),
            self::CODE_MISSING_INDEX
        );
    }

    public static function missingToken(string $formFieldName): self
    {
        return new self(
            \sprintf('Missing token form post with name "%s"', $formFieldName),
            self::CODE_MISSING_TOKEN
        );
    }

    public static function indexTypeError(string $value): self
    {
        return new self(
            \sprintf('Index form post value expected to be string, "%s" given', \gettype($value)),
            self::CODE_TYPE_INDEX
        );
    }

    public static function tokenTypeError(string $value): self
    {
        return new self(
            \sprintf('Token form post value expected to be string, "%s" given', \gettype($value)),
            self::CODE_TYPE_TOKEN
        );
    }
}
