<?php
namespace Test\Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class SessionTest
{
    private function subject(): \Lucinda\WebSecurity\Configuration\Persistence\Session
    {
        return new \Lucinda\WebSecurity\Configuration\Persistence\Session(simplexml_load_string('<session parameter_name="sid" expiration="50" is_http_only="1" is_https_only="0" same_site="Strict" handler="Handler"/>'));
    }

    public function getParameterName()
    {
        return (new Strings($this->subject()->getParameterName()))->assertEquals("sid");
    }

    public function getExpirationTime()
    {
        return (new Integers($this->subject()->getExpirationTime()))->assertEquals(50);
    }

    public function getIsHttpOnly()
    {
        return (new Booleans($this->subject()->getIsHttpOnly() === true))->assertTrue();
    }

    public function getIsHttpsOnly()
    {
        return (new Booleans($this->subject()->getIsHttpsOnly() === false))->assertTrue();
    }

    public function getSameSite()
    {
        return (new Strings($this->subject()->getSameSite()))->assertEquals("Strict");
    }

    public function getHandler()
    {
        return (new Strings($this->subject()->getHandler()))->assertEquals("Handler");
    }
}
