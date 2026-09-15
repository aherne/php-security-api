<?php

namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Arrays;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class AuthorizationTest
{
    public function getMethods()
    {
        $methods = Fixture::configuration()->getAuthorization()->getMethods();

        return (new Arrays($methods))->assertSize(1);
    }
}
