<?php
namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class CsrfTest
{
    private function subject(): \Lucinda\WebSecurity\Configuration\Csrf
    {
        return new \Lucinda\WebSecurity\Configuration\Csrf(simplexml_load_string('<xml><csrf secret="secret" expiration="42"/></xml>'));
    }

    public function getSecret()
    {
        return (new Strings($this->subject()->getSecret()))->assertEquals("secret");
    }

    public function getExpirationTime()
    {
        return (new Integers($this->subject()->getExpirationTime()))->assertEquals(42);
    }
}
