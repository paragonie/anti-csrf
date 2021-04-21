<?php
declare(strict_types=1);

namespace ParagonIE\AntiCSRF;

/**
 * Class Reusable
 *
 * Reusable variant of the AntiCSRF class.
 * Tokens don't expire after a single use. This is dangerous, but allows them
 * to be used in AJAX forms.
 *
 * We will not award any bug bounties for any vulnerabilities found in the
 * Reusable class that are not also present in the main class, as we believe
 * this use-case to be a significant security downgrade.
 *
 * @package ParagonIE\AntiCSRF
 */
class Reusable extends AntiCSRF
{
    /**
     * @var \DateInterval|null
     */
    protected $tokenLifetime = null;

    /**
     * @param \DateInterval $interval
     * @return self
     */
    public function setTokenLifetime(\DateInterval $interval): self
    {
        $this->tokenLifetime = $interval;
        return $this;
    }

    /**
     * For figuring
     *
     * @param array $args
     * @return array
     */
    protected function buildBasicToken(array $args = []): array
    {
        $args['created-date'] = (new \DateTime())->format(\DateTime::ATOM);
        return $args;
    }

    /**
     * Use this to change the configuration settings.
     * Only use this if you know what you are doing.
     *
     * @param array $options
     * @return AntiCSRF
     */
    public function reconfigure(array $options = []): AntiCSRF
    {
        /** @var string $opt */
        /** @var \DateInterval $val */
        foreach ($options as $opt => $val) {
            switch ($opt) {
                case 'tokenLifetime':
                    if ($val instanceof \DateInterval) {
                        $this->tokenLifetime = $val;
                    }
                    break;
            }
        }
        return parent::reconfigure($options);
    }

    /**
     * @param array<string, string> $token
     * @return bool
     */
    public function deleteToken(array $token): bool
    {
        if (empty($token['created-date'])) {
            return true;
        }
        if (!($this->tokenLifetime instanceof \DateInterval)) {
            return false;
        }
        $dateTime = (new \DateTime($token['created-date']))->add($this->tokenLifetime);
        $now = new \DateTime();
        return $dateTime >= $now ? false : true;
    }
}
