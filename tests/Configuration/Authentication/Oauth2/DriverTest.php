<?php

namespace Test\Lucinda\WebSecurity\Configuration\Authentication\Oauth2;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2\Driver;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class DriverTest
{
    private function configuration(): Driver
    {
        return new Driver(Fixture::node("oauth-driver"));
    }

    public function getName()
    {
        $actual = $this->configuration()->getName();

        return (new Strings($actual))->assertEquals("example");
    }

    public function getPageLogin()
    {
        $actual = $this->configuration()->getPageLogin();

        return (new Strings($actual))->assertEquals("oauth/callback");
    }
}
