<?php
namespace Resonantcore\AntiCSRF;

/**
 * Copyright (c) 2015 Resonant Core <https://resonantcore.net>
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
 * If you would like to use this library under different terms, please
 * contact Resonant Core to inquire about a license exemption.
 */
class AntiCSRF
{
    const FORM_INDEX = '_CSRF_INDEX';
    const FORM_TOKEN = '_CSRF_TOKEN';
    const SESSION_INDEX = 'CSRF';
    const HASH_ALGO = 'sha256';
    const RECYCLE_AFTER = 65535;

    public static $hmac_ip = true;
    public static $expire_old = false;

    /**
     * Insert a CSRF token to a form
     *
     * @param $lockto This CSRF token is only valid for this HTTP request endpoint
     * @param $echo if true, echo instead of returning
     * @return string
     */
    public static function insertToken($lockto = null, $echo = true)
    {
        $ret = '';

        if (!isset($_SESSION[self::SESSION_INDEX])) {
            $_SESSION[self::SESSION_INDEX] = [];
        }

        if (empty($lockto)) {
            $lockto = $_SERVER['REQUEST_URI'];
        }

        if (\preg_match('#/$#', $lockto)) {
            $lockto = substr($lockto, 0, strlen($lockto) - 1);
        }

        list($index, $token) = self::generateToken($lockto);

        $ret .= "<!--\n-->".
            "<input type=\"hidden\"".
            " name=\"".self::FORM_INDEX."\"".
            " value=\"".self::noHTML($index)."\"".
            " />";

        if (self::$hmac_ip !== false) {
            // Use HMAC to only allow this particular IP to send this request
            $token = \base64_encode(
                \hash_hmac(
                    self::HASH_ALGO,
                    isset($_SERVER['REMOTE_ADDR'])
                        ? $_SERVER['REMOTE_ADDR']
                        : '127.0.0.1',
                    \base64_decode($token),
                    true
                )
            );
        }


        $ret .= "<!--\n-->".
            "<input type=\"hidden\"".
            " name=\"".self::FORM_TOKEN."\"".
            " value=\"".self::noHTML($token)."\"".
            " />";

        if ($echo) {
            echo $ret;
            return;
        }
        return $ret;
    }

    /**
     * Validate a request based on $_SESSION and $_POST data
     *
     * @return boolean
     */
    public static function validateRequest()
    {
        if (!isset($_SESSION[self::SESSION_INDEX])) {
            // We don't even have a session array initialized
            $_SESSION[self::SESSION_INDEX] = [];
            return false;
        }

        if (!isset($_POST[self::FORM_INDEX]) || !isset($_POST[self::FORM_TOKEN])) {
            // User must transmit a complete index/token pair
            return false;
        }

        // Let's pull the POST data
        $index = $_POST[self::FORM_INDEX];
        $token = $_POST[self::FORM_TOKEN];

        if (!isset($_SESSION[self::SESSION_INDEX][$index])) {
            // CSRF Token not found
            return false;
        }

        // Grab the value stored at $index
        $stored = $_SESSION[self::SESSION_INDEX][$index];

        // We don't need this anymore
        unset($_SESSION[self::SESSION_INDEX][$index]);

        // Which form action="" is this token locked to?
        $lockto = $_SERVER['REQUEST_URI'];
        if (\preg_match('#/$#', $lockto)) {
            // Trailing slashes are to be ignored
            $lockto = substr($lockto, 0, strlen($lockto) - 1);
        }

        if (!self::hash_equals($lockto, $stored['lockto'])) {
            // Form target did not match the request this token is locked to!
            return false;
        }

        // This is the expected token value
        if (self::$hmac_ip === false) {
            // We just stored it wholesale
            $expected = $stored['token'];
        } else {
            // We mixed in the client IP address to generate the output
            $expected = \base64_encode(
                \hash_hmac(
                    self::HASH_ALGO,
                    isset($_SERVER['REMOTE_ADDR'])
                        ? $_SERVER['REMOTE_ADDR']
                        : '127.0.0.1',
                    \base64_decode($stored['token']),
                    true
                )
            );
        }

        return self::hash_equals($token, $expected);
    }

    /**
     * Generate, store, and return the index and token
     *
     * @param string $lockto What URI endpoint this is valid for
     * @return array [string, string]
     */
    private static function generateToken($lockto)
    {
        $index = \base64_encode(self::random_bytes(18));
        $token = \base64_encode(self::random_bytes(32));

        $_SESSION[self::SESSION_INDEX][$index] = [
            'created' => \intval(\date('YmdHis')),
            'uri' => isset($_SERVER['REQUEST_URI'])
                ? $_SERVER['REQUEST_URI']
                : $_SERVER['SCRIPT_NAME'],
            'token' => $token
        ];
        if (\preg_match('#/$#', $lockto)) {
            $lockto = self::subString($lockto, 0, self::stringLength($lockto) - 1);
        }
        $_SESSION[self::SESSION_INDEX][$index]['lockto'] = $lockto;

        self::recycleTokens();
        return [ $index, $token ];
    }

    /**
     * Enforce an upper limit on the number of tokens stored in session state
     * by removing the oldest tokens first.
     */
    private static function recycleTokens()
    {
        if (!self::$expire_old) {
            // This is turned off.
            return;
        }
        // Sort by creation time
        \uasort($_SESSION[self::SESSION_INDEX], function($a, $b) {
            return $a['created'] - $b['created'];
        });

        if (\count($_SESSION[self::SESSION_INDEX]) > self::RECYCLE_AFTER) {
            // Let's knock off the oldest one
            \array_shift($_SESSION[self::SESSION_INDEX]);
        }
    }

    /**
     * Generate a cryptographically secure pseudorandom number
     *
     * @param integer $bytes - Number of bytes needed
     * @param bool $fail_open - Trigger a warning rather than throwing an exception
     * @return string
     */
    private static function random_bytes($bytes)
    {
        if (!\is_int($bytes) || $bytes < 1) {
            throw new \Exception("\$bytes must be a positive integer greater than zero.");
        }

        if (function_exists('\mcrypt_create_iv')) {
            // mcrypt_create_iv() is smart; uses Windows APIs to get entropy if it needs to
            return \mcrypt_create_iv($bytes, MCRYPT_DEV_URANDOM);
        }

        if (\is_readable('/dev/urandom')) {
            // If /dev/urandom is readable, grab some entropy
            $fp = \fopen('/dev/urandom', 'rb');

            // Turn off buffering so we don't waste (8192-$bytes) bytes of urandom entropy
            stream_set_read_buffer($fp, 0);

            $buf = \fread($fp, $bytes);
            \fclose($fp);

            if ($buf !== false) {
                return $buf;
            }
        }

        return \openssl_random_pseudo_bytes($bytes);
    }

    /**
     * Wrapper for htmlentities()
     *
     * @param string $untrusted
     * @return string
     */
    private static function noHTML($untrusted)
    {
        return \htmlentities($untrusted, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * Compare strings without leaking timing information.
     * Use PHP's native hash_equals() if it is available.
     * Otherwise, use a double-HMAC with a random nonce.
     *
     * @param string $a first string
     * @param string $b second string
     * @return boolean
     */
    private static function hash_equals($a, $b)
    {
        if (\function_exists('\\hash_equals')) {
            return \hash_equals($a, $b);
        }

        $nonce = self::random_bytes(32);
        return \hash_hmac('sha256', $a, $nonce) === \hash_hmac('sha256', $b, $nonce);
    }

    /**
     * Binary-safe substr() implementation
     *
     * @param string $string
     * @param int $start
     * @param int|null $length
     * @return string
     */
    private static function subString($str, $start, $length = null)
    {
        if (\function_exists('\\mb_substr')) {
            return \mb_substr($str, $start, $length, '8bit');
        }
    }

    /**
     * Binary-safe strlen() implementation
     *
     * @param string $string
     * @return string
     */
    private static function stringLength($str)
    {
        if (\function_exists('\\mb_substr')) {
            return \mb_strlen($str, '8bit');
        }
        return \strlen($str);
    }
}
