<?php
use \ParagonIE\AntiCSRF\AntiCSRF;

class AntiCSRFTest extends PHPUnit_Framework_TestCase
{
    /**
     * @covers \Resonantcore\AntiCSRF\AntiCSRF::insertToken()
     */
    public function testInsertToken()
    {
        $post = [];
        $session = [];
        $server = $_SERVER;

        $csrft = new AntiCSRF($post, $session, $server);
        $token_html = $csrft->insertToken('', false);
        
        $idx = $csrft->getSessionIndex();
        $this->assertFalse(
            empty($csrft->session[$idx])
        );

        $this->assertFalse(
            empty($session[$idx])
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
        $this->assertSame( 
            [
                $csrft->getFormIndex(),
                $csrft->getFormToken(),
            ], 
            \array_keys($result)
        );
    }
}
