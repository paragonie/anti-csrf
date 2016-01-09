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
        $csrft = new AntiCSRF();
        $csrft->insertToken();
        $token_html = ob_get_clean();
        $idx = $csrft->getSessionIndex();

        $this->assertFalse(
            empty($csrft->session[$idx])
        );

        $this->assertFalse(
            empty($_SESSION[$idx])
        );

        $this->assertContains("<input", $token_html);
    }

    /**
     * @covers \Resonantcore\AntiCSRF\AntiCSRF::getTokenArray()
     */
    public function testGetTokenArray()
    {
        @session_start();

        $csrft = new AntiCSRF();
        $result = $csrft->getTokenArray();

        $this->assertFalse(
            empty($csrft->session[$csrft->getSessionIndex()])
        );
        $this->assertSame( [
	        $csrft->getFormIndex(),
	        $csrft->getFormToken(),
        ], array_keys( $result ) );
    }
}
