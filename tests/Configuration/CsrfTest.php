<?php

namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Csrf;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class CsrfTest
{
    private function configuration(): Csrf
    {
        return new Csrf(Fixture::node("csrf"));
    }

    public function getSecret()
    {
        $actual = $this->configuration()->getSecret();

        return (new Strings($actual))->assertEquals("secret");
    }

    public function getExpirationTime()
    {
        $actual = $this->configuration()->getExpirationTime();

        return (new Integers($actual))->assertEquals(720);
    }
}
