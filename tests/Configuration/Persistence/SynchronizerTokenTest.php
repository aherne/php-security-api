<?php
namespace Test\Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class SynchronizerTokenTest
{
    private function subject(): \Lucinda\WebSecurity\Configuration\Persistence\SynchronizerToken
    {
        return new \Lucinda\WebSecurity\Configuration\Persistence\SynchronizerToken(simplexml_load_string('<synchronizer_token secret="secret" expiration="80" regeneration="9"/>'));
    }

    public function getSecret()
    {
        return (new Strings($this->subject()->getSecret()))->assertEquals("secret");
    }

    public function getExpirationTime()
    {
        return (new Integers($this->subject()->getExpirationTime()))->assertEquals(80);
    }

    public function getRegenerationTime()
    {
        return (new Integers($this->subject()->getRegenerationTime()))->assertEquals(9);
    }
}
