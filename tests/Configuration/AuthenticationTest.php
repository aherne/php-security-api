<?php

namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Configuration\Authentication;
use Lucinda\WebSecurity\Configuration\Authentication\Logout;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class AuthenticationTest
{
    private function configuration(): Authentication
    {
        return Fixture::configuration()->getAuthentication();
    }

    public function getLoginMethods()
    {
        $methods = $this->configuration()->getLoginMethods();

        return (new Arrays($methods))->assertSize(1);
    }

    public function getLogoutMethod()
    {
        $method = $this->configuration()->getLogoutMethod();

        return (new Objects($method))->assertInstanceOf(Logout::class);
    }
}
