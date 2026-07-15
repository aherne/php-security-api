<?php
namespace Test\Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class RememberMeTest
{
    private function subject(): \Lucinda\WebSecurity\Configuration\Persistence\RememberMe
    {
        return new \Lucinda\WebSecurity\Configuration\Persistence\RememberMe(simplexml_load_string('<remember_me parameter_name="remember" secret="secret" expiration="70" is_http_only="1" is_https_only="1" same_site="Lax"/>'));
    }

    public function getParameterName()
    {
        return (new Strings($this->subject()->getParameterName()))->assertEquals("remember");
    }

    public function getSecret()
    {
        return (new Strings($this->subject()->getSecret()))->assertEquals("secret");
    }

    public function getExpirationTime()
    {
        return (new Integers($this->subject()->getExpirationTime()))->assertEquals(70);
    }

    public function getIsHttpOnly()
    {
        return (new Booleans($this->subject()->getIsHttpOnly() === true))->assertTrue();
    }

    public function getIsHttpsOnly()
    {
        return (new Booleans($this->subject()->getIsHttpsOnly() === true))->assertTrue();
    }

    public function getSameSite()
    {
        return (new Strings($this->subject()->getSameSite()))->assertEquals("Lax");
    }
}
