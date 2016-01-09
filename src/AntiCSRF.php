<?php
namespace ParagonIE\AntiCSRF;

/**
 * Copyright (c) 2015 - 2016 Paragon Initiative Enterprises <https://paragonie.com>
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
 * Copyright (c) 2015 - 2016 Paragon Initiative Enterprises
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
 * contact Resonant Core to inquire about a license exemption.
 */
class AntiCSRF
{
    protected $formIndex = '_CSRF_INDEX';
    protected $formToken = '_CSRF_TOKEN';
    protected $sessionIndex = 'CSRF';
    protected $hashAlgo = 'sha256';
    protected $recycle_after = 65535;
    protected $hmac_ip = true;
    protected $expire_old = false;
    
    // Injected; defaults to references to superglobals
    public $post;
    public $session;
    public $server;

    /**
     * NULL is not a valid array type
     * 
     * @param array $post
     * @param array $session
     * @param array $server
     */
    public function __construct(
        &$post = null,
        &$session = null,
        &$server = null
    ) {
        if ($post !== null) {
            $this->post =& $post;
        } else {
            $this->post =& $_POST;
        }
        
        if ($server !== null) {
            $this->server =& $server;
        } else {
            $this->server =& $_SERVER;
        }

        if ($session === null && isset($_SESSION)) {
            $this->session =& $_SESSION;
        } else {
            $this->session =& $session;
        }
    }

    /**
     * Insert a CSRF token to a form
     *
     * @param string $lockTo This CSRF token is only valid for this HTTP request endpoint
     * @param boolean $echo if true, echo instead of returning
     * @return string
     */
    public function insertToken($lockTo = null, $echo = true)
    {
	    $token_array = $this->getTokenArray($lockTo);
	    $ret = \implode(
	    	\array_map(
        		function($key, $value) {
    			    return "<!--\n-->".
    		            "<input type=\"hidden\"".
    		            " name=\"".$key."\"".
    		            " value=\"".self::noHTML($value)."\"".
    		            " />";
    	        },
    	        \array_keys($token_array),
    	        $token_array
            )
        );
	    if ($echo) {
		    echo $ret;
		    return null;
	    }
        return $ret;
    }
    
    public function getSessionIndex()
    {
        return $this->sessionIndex;
    }
    
    public function getFormIndex()
    {
        return $this->formIndex;
    }
    
    public function getFormToken()
    {
        return $this->formToken;
    }

	/**
	 * Retrieve a token array for unit testing endpoints
	 *
	 * @return array
	 */
	public function getTokenArray($lockTo = null)
	{
        if (!isset($this->session[$this->sessionIndex])) {
            $this->session[$this->sessionIndex] = [];
        }

        if (empty($lockTo)) {
            $lockTo = isset($this->server['REQUEST_URI'])
                ? $this->server['REQUEST_URI']
                : '/';
        }

        if (\preg_match('#/$#', $lockTo)) {
            $lockTo = \substr($lockTo, 0, strlen($lockTo) - 1);
        }

        list($index, $token) = $this->generateToken($lockTo);

        if ($this->hmac_ip !== false) {
            // Use HMAC to only allow this particular IP to send this request
            $token = $this->encode(
                \hash_hmac(
                    $this->hashAlgo,
                    isset($this->server['REMOTE_ADDR'])
                        ? $this->server['REMOTE_ADDR']
                        : '127.0.0.1',
                    \base64_decode($token),
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
     * @return boolean
     */
    public function validateRequest()
    {
        if (!isset($this->session[$this->sessionIndex])) {
            // We don't even have a session array initialized
            $this->session[$this->sessionIndex] = [];
            return false;
        }

        if (
            !isset($this->post[$this->formIndex]) ||
            !isset($this->post[$this->formToken])
        ) {
            // User must transmit a complete index/token pair
            return false;
        }

        // Let's pull the POST data
        $index = $this->post[$this->formIndex];
        $token = $this->post[$this->formToken];

        if (!isset($this->session[$this->sessionIndex][$index])) {
            // CSRF Token not found
            return false;
        }

        // Grab the value stored at $index
        $stored = $this->session[$this->sessionIndex][$index];

        // We don't need this anymore
        unset($this->session[$this->sessionIndex][$index]);

        // Which form action="" is this token locked to?
        $lockTo = $this->server['REQUEST_URI'];
        if (\preg_match('#/$#', $lockTo)) {
            // Trailing slashes are to be ignored
            $lockTo = substr($lockTo, 0, strlen($lockTo) - 1);
        }

        if (!\hash_equals($lockTo, $stored['lockTo'])) {
            // Form target did not match the request this token is locked to!
            return false;
        }

        // This is the expected token value
        if ($this->hmac_ip === false) {
            // We just stored it wholesale
            $expected = $stored['token'];
        } else {
            // We mixed in the client IP address to generate the output
            $expected = $this->encode(
                \hash_hmac(
                    self::HASH_ALGO,
                    isset($this->server['REMOTE_ADDR'])
                        ? $this->server['REMOTE_ADDR']
                        : '127.0.0.1',
                    \base64_decode($stored['token']),
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
     */
    public function reconfigure(array $options = [])
    {
        foreach ($options as $opt => $val) {
            switch ($opt) {
                case 'formIndex':
                case 'formToken':
                case 'sessionIndex':
                case 'recycle_after':
                case 'hmac_ip':
                case 'expire_old':
                    $this->${$opt} = $val;
                    break;
                case 'hashAlgo':
                    if (\in_array($val, \hash_algos())) {
                        $this->hashAlgo = $val;
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
     */
    protected function generateToken($lockTo)
    {
        $index = $this->encode(
            \random_bytes(18)
        );
        $token = $this->encode(
            \random_bytes(32)
        );

        $this->session[$this->sessionIndex][$index] = [
            'created' => \intval(
                \date('YmdHis')
            ),
            'uri' => isset($this->server['REQUEST_URI'])
                ? $this->server['REQUEST_URI']
                : $this->server['SCRIPT_NAME'],
            'token' => $token
        ];
        if (\preg_match('#/$#', $lockTo)) {
            $lockTo = self::subString($lockTo, 0, self::stringLength($lockTo) - 1);
        }
        $this->session[$this->sessionIndex][$index]['lockTo'] = $lockTo;

        $this->recycleTokens();
        return [$index, $token];
    }

    /**
     * Enforce an upper limit on the number of tokens stored in session state
     * by removing the oldest tokens first.
     */
    protected function recycleTokens()
    {
        if (!$this->expire_old) {
            // This is turned off.
            return;
        }
        // Sort by creation time
        \uasort(
            $this->session[$this->sessionIndex],
            function($a, $b) {
                return $a['created'] - $b['created'];
            }
        );

        while (\count($this->session[$this->sessionIndex]) > $this->recycle_after) {
            // Let's knock off the oldest one
            \array_shift($this->session[$this->sessionIndex]);
        }
        return $this;
    }

    /**
     * Wrapper for htmlentities()
     *
     * @param string $untrusted
     * @return string
     */
    protected static function noHTML($untrusted)
    {
        return \htmlentities($untrusted, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Encode string with base64, but strip padding.
     * PHP base64_decode does not croak on that.
     *
     * @param string $s
     * @return string
     */
    protected static function encode($s)
    {
        return \rtrim(
            \base64_encode($s),
            '='
        );
    }

    /**
     * Binary-safe substr() implementation
     *
     * @param string $str
     * @param int $start
     * @param int|null $length
     * @return string
     */
    protected static function subString($str, $start, $length = null)
    {
        if (\function_exists('\\mb_substr')) {
            return \mb_substr($str, $start, $length, '8bit');
        }
        return \substr($str, $start, $length);
    }

    /**
     * Binary-safe strlen() implementation
     *
     * @param string $str
     * @return string
     */
    protected static function stringLength($str)
    {
        if (\function_exists('\\mb_substr')) {
            return \mb_strlen($str, '8bit');
        }
        return \strlen($str);
    }
}
