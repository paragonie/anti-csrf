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
        $this->assertContains("<input", $token_html);
    }

    /**
     * @covers \Resonantcore\AntiCSRF\AntiCSRF::getTokenArray()
     */
    public function testGetTokenArray()
    {
        @session_start();

        $result = AntiCSRF::getTokenArray();

        $this->assertFalse(
            empty($_SESSION[AntiCSRF::SESSION_INDEX])
        );
        $this->assertSame( [
	        AntiCSRF::FORM_INDEX,
	        AntiCSRF::FORM_TOKEN,
        ], array_keys( $result ) );
    }
}
