<?php
namespace Test\Lucinda\WebSecurity\Configuration\Authentication\Oauth2;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class DriverTest
{
    private function subject(): \Lucinda\WebSecurity\Configuration\Authentication\Oauth2\Driver
    {
        return new \Lucinda\WebSecurity\Configuration\Authentication\Oauth2\Driver(simplexml_load_string('<driver name="github" login="login/github"/>'));
    }

    public function getName()
    {
        return (new Strings($this->subject()->getName()))->assertEquals("github");
    }

    public function getPageLogin()
    {
        return (new Strings($this->subject()->getPageLogin()))->assertEquals("login/github");
    }
}
