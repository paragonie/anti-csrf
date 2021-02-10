<?php
declare(strict_types=1);
namespace ParagonIE\AntiCSRF;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use Error;

/**
 * Copyright (c) 2015 - 2018 Paragon Initiative Enterprises <https://paragonie.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *******************************************************************************
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 - 2018 Paragon Initiative Enterprises
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *
 * If you would like to use this library under different terms, please
 * contact Paragon Initiative Enterprises to inquire about a license exemption.
 */
class AntiCSRF
{
    /**
     * @var string
     */
    protected $formIndex = '_CSRF_INDEX';

    /**
     * @var string
     */
    protected $formToken = '_CSRF_TOKEN';

    /**
     * @var string
     */
    protected $sessionIndex = 'CSRF';

    /**
     * @var string
     */
    protected $hashAlgo = 'sha256';

    /**
     * @var int
     */
    protected $recycle_after = 65535;

    /**
     * @var bool
     */
    protected $hmac_ip = true;

    /**
     * @var bool
     */
    protected $hmac_ua = true;

    /**
     * @var bool
     */
    protected $expire_old = false;

    /**
     * @var string
     */
    protected $lock_type = 'REQUEST_URI';

    // Injected; defaults to references to superglobals

    /**
     * @var array
     */
    public $post = [];

    /**
     * @var array
     */
    public $session = [];

    /**
     * @var bool
     */
    public $useNativeSession = false;

    /**
     * @var array
     */
    public $server = [];

    /**
     * NULL is not a valid array type
     *
     * @param array $post
     * @param array $session
     * @param array $server
     * @throws Error
     */
    public function __construct(
        &$post = null,
        &$session = null,
        &$server = null
    ) {
        if (!\is_null($post)) {
            $this->post =& $post;
        } else {
            $this->post =& $_POST;
        }

        if (!\is_null($server)) {
            $this->server =& $server;
        } else {
            $this->server =& $_SERVER;
        }

        if (!\is_null($session)) {
            $this->session =& $session;
        } elseif (isset($_SESSION)) {
            if (\is_array($_SESSION)) {
                $this->session =& $_SESSION;
                $this->useNativeSession = true;
            }
        } else {
            throw new Error('No session available for persistence');
        }
    }

    /**
     * Allow derived classes to inject arguments.
     *
     * @param array $args
     * @return array
     */
    protected function buildBasicToken(array $args = []): array
    {
        return $args;
    }

    /**
     * @param array $token
     * @return bool
     */
    public function deleteToken(array $token): bool
    {
        return true;
    }

    /**
     * Insert a CSRF token to a form
     *
     * @param string $lockTo This CSRF token is only valid for this HTTP request endpoint
     * @param bool $echo if true, echo instead of returning
     * @return string
     * @throws \Exception
     * @throws \TypeError
     */
    public function insertToken(string $lockTo = '', bool $echo = true): string
    {
        $token_array = $this->getTokenArray($lockTo);
        $ret = \implode(
            \array_map(
                function(string $key, string $value): string {
                    return "<!--\n-->".
                        "<input type=\"hidden\"" .
                        " name=\"" . $key . "\"" .
                        " value=\"" . self::noHTML($value) . "\"" .
                        " />";
                },
                \array_keys($token_array),
                $token_array
            )
        );
        if ($echo) {
            echo $ret;
            return '';
        }
        return $ret;
    }

    /**
     * @return string
     */
    public function getSessionIndex(): string
    {
        return $this->sessionIndex;
    }

    /**
     * @return string
     */
    public function getFormIndex(): string
    {
        return $this->formIndex;
    }

    /**
     * @return string
     */
    public function getFormToken(): string
    {
        return $this->formToken;
    }

    /**
     * @return string
     */
    public function getLockType(): string
    {
        return $this->lock_type;
    }

    /**
     * Retrieve a token array for unit testing endpoints
     *
     * @param string $lockTo
     * @return array
     *
     * @throws \Exception
     * @throws \TypeError
     */
    public function getTokenArray(string $lockTo = ''): array
    {
        if ($this->useNativeSession) {
            if (!isset($_SESSION[$this->sessionIndex])) {
                $_SESSION[$this->sessionIndex] = [];
            }
        } elseif (!isset($this->session[$this->sessionIndex])) {
            $this->session[$this->sessionIndex] = [];
        }

        if (empty($lockTo)) {
            /** @var string $lockTo */
            $lockTo = isset($this->server['REQUEST_URI'])
                ? $this->server['REQUEST_URI']
                : '/';
        }

        if (\preg_match('#/$#', $lockTo)) {
            $lockTo = Binary::safeSubstr($lockTo, 0, Binary::safeStrlen($lockTo) - 1);
        }

        list($index, $token) = $this->generateToken($lockTo);

        if ($this->hmac_ip !== false || $this->hmac_ua !== false) {
            // Use HMAC to only allow this particular IP to send this request
            $token = Base64UrlSafe::encode(
                \hash_hmac(
                    $this->hashAlgo,
                    (($this->hmac_ip !== false && $this->hmac_ua !== false) ? (isset($this->server['REMOTE_ADDR']) ? (string) $this->server['REMOTE_ADDR'] : '127.0.0.1').(isset($this->server['HTTP_USER_AGENT']) ? (string) $this->server['HTTP_USER_AGENT'] : 'Mozilla') : (($this->hmac_ip !== true && $this->hmac_ua !== false) ? (isset($this->server['HTTP_USER_AGENT']) ? (string) $this->server['HTTP_USER_AGENT'] : 'Mozilla') : (isset($this->server['REMOTE_ADDR']) ? (string) $this->server['REMOTE_ADDR'] : '127.0.0.1'))),
                    (string) Base64UrlSafe::decode($token),
                    true
                )
            );
        }

        return [
            $this->formIndex => $index,
            $this->formToken => $token,
        ];
    }


    /**
     * Validate a request based on $this->session and $this->post data
     *
     * @return bool
     * @throws \TypeError
     */
    public function validateRequest(): bool
    {
        if ($this->useNativeSession) {
            if (!isset($_SESSION[$this->sessionIndex])) {
                return false;
            }
            /** @var array<string, array<string, mixed>> $sess */
            $sess =& $_SESSION[$this->sessionIndex];
        } else {
            if (!isset($this->session[$this->sessionIndex])) {
                return false;
            }
            /** @var array<string, array<string, mixed>> $sess */
            $sess =& $this->session[$this->sessionIndex];
        }

        if (
            empty($this->post[$this->formIndex]) ||
            empty($this->post[$this->formToken])
        ) {
            // User must transmit a complete index/token pair
            return false;
        }

        // Let's pull the POST data
        /** @var string $index */
        $index = $this->post[$this->formIndex];
        /** @var string $token */
        $token = $this->post[$this->formToken];
        if (!\is_string($index) || !\is_string($token)) {
            return false;
        }

        if (!isset($sess[$index])) {
            // CSRF Token not found
            return false;
        }

        if (!\is_string($index) || !\is_string($token)) {
            return false;
        }

        // Grab the value stored at $index
        /** @var array<string, mixed> $stored */
        $stored = $sess[$index];

        // We don't need this anymore
        if ($this->deleteToken($sess[$index])) {
            unset($sess[$index]);
        }

        // Which form action="" is this token locked to?
        /** @var string $lockTo */
        $lockTo = $this->server[$this->lock_type];
        if (\preg_match('#/$#', $lockTo)) {
            // Trailing slashes are to be ignored
            $lockTo = Binary::safeSubstr(
                $lockTo,
                0,
                Binary::safeStrlen($lockTo) - 1
            );
        }

        if (!\hash_equals($lockTo, (string) $stored['lockTo'])) {
            // Form target did not match the request this token is locked to!
            return false;
        }

        // This is the expected token value
        if ($this->hmac_ip === false && $this -> hmac_ua === false) {
            // We just stored it wholesale
            /** @var string $expected */
            $expected = $stored['token'];
        } else {
            // We mixed in the client IP address to generate the output
            /** @var string $expected */
            $expected = Base64UrlSafe::encode(
                \hash_hmac(
                    $this->hashAlgo,
                    (($this->hmac_ip !== false && $this->hmac_ua !== false) ? (isset($this->server['REMOTE_ADDR']) ? (string) $this->server['REMOTE_ADDR'] : '127.0.0.1').(isset($this->server['HTTP_USER_AGENT']) ? (string) $this->server['HTTP_USER_AGENT'] : 'Mozilla') : (($this->hmac_ip !== true && $this->hmac_ua !== false) ? (isset($this->server['HTTP_USER_AGENT']) ? (string) $this->server['HTTP_USER_AGENT'] : 'Mozilla') : (isset($this->server['REMOTE_ADDR']) ? (string) $this->server['REMOTE_ADDR'] : '127.0.0.1'))),
                    (string) Base64UrlSafe::decode((string) $stored['token']),
                    true
                )
            );
        }
        return \hash_equals($token, $expected);
    }

    /**
     * Use this to change the configuration settings.
     * Only use this if you know what you are doing.
     *
     * @param array $options
     * @return self
     */
    public function reconfigure(array $options = []): self
    {
        /** @var string $opt */
        /** @var string $val */
        foreach ($options as $opt => $val) {
            switch ($opt) {
                case 'formIndex':
                case 'formToken':
                case 'sessionIndex':
                case 'useNativeSession':
                case 'recycle_after':    
                case 'hmac_ip':
                case 'hmac_ua':
                case 'expire_old':
                    /** @psalm-suppress MixedAssignment */
                    $this->$opt = $val;
                    break;
                case 'hashAlgo':
                    if (\in_array($val, \hash_algos(), true)) {
                        $this->hashAlgo = (string) $val;
                    }
                    break;
                case 'lock_type':
                    if (\in_array($val, array('REQUEST_URI','PATH_INFO'), true)) {
                        $this->lock_type = (string) $val;
                    }
                    break;
            }
        }
        return $this;
    }

    /**
     * Generate, store, and return the index and token
     *
     * @param string $lockTo What URI endpoint this is valid for
     * @return string[]
     * @throws \TypeError
     * @throws \Exception
     */
    protected function generateToken(string $lockTo): array
    {
        $index = Base64UrlSafe::encode(\random_bytes(18));
        $token = Base64UrlSafe::encode(\random_bytes(33));

        $new = $this->buildBasicToken([
            'created' => \intval(
                \date('YmdHis')
            ),
            'uri' => isset($this->server['REQUEST_URI'])
                ? $this->server['REQUEST_URI']
                : $this->server['SCRIPT_NAME'],
            'token' => $token
        ]);

        if (\preg_match('#/$#', $lockTo)) {
            $lockTo = Binary::safeSubstr(
                $lockTo,
                0,
                Binary::safeStrlen($lockTo) - 1
            );
        }

        if ($this->useNativeSession) {
            /** @var array<string, array<string, string|int>> $sess */
            $sess =& $_SESSION[$this->sessionIndex];
        } else {
            /** @var array<string, array<string, string|int>> $sess */
            $sess =& $this->session[$this->sessionIndex];
        }
        $sess[$index] = $new;
        $sess[$index]['lockTo'] = $lockTo;

        $this->recycleTokens();
        return [$index, $token];
    }

    /**
     * Enforce an upper limit on the number of tokens stored in session state
     * by removing the oldest tokens first.
     *
     * @return self
     */
    protected function recycleTokens()
    {
        if (!$this->expire_old) {
            // This is turned off.
            return $this;
        }

        if ($this->useNativeSession) {
            /** @var array<string, array<string, string|int>> $sess */
            $sess =& $_SESSION[$this->sessionIndex];
        } else {
            /** @var array<string, array<string, string|int>> $sess */
            $sess =& $this->session[$this->sessionIndex];
        }
        // Sort by creation time
        \uasort(
            $sess,
            function (array $a, array $b): int {
                return (int) ($a['created'] <=> $b['created']);
            }
        );
        while (\count($sess) > $this->recycle_after) {
            // Let's knock off the oldest one
            \array_shift($sess);
        }
        return $this;
    }

    /**
     * Wrapper for htmlentities()
     *
     * @param string $untrusted
     * @return string
     */
    protected static function noHTML(string $untrusted): string
    {
        return \htmlentities($untrusted, ENT_QUOTES, 'UTF-8');
    }
}
