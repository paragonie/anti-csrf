<?php

use \ParagonIE\AntiCSRF\AntiCSRF;

class AntiCSRFTest extends PHPUnit_Framework_TestCase
{
    /**
     * @covers \Resonantcore\AntiCSRF\AntiCSRF::insertToken()
     */
    public function testInsertToken()
    {
        @session_start();

        ob_start();
        AntiCSRF::insertToken();
        $token_html = ob_get_clean();

        $this->assertFalse(
            empty($_SESSION[AntiCSRF::SESSION_INDEX])
        );
    }
}
