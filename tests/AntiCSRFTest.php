<?php
use \ParagonIE\AntiCSRF\AntiCSRF;

class AntiCSRFTest extends PHPUnit_Framework_TestCase
{
    /**
     * @covers AntiCSRF::insertToken()
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
     * @covers AntiCSRF::getTokenArray()
     */
    public function testGetTokenArray()
    {
        @session_start();

        try {
            $csrft = new AntiCSRF();
        } catch (\Throwable $ex) {
            $post = [];
            $session = [];
            $server = $_SERVER;

            $csrft = new AntiCSRF($post, $session, $server);
        }
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
