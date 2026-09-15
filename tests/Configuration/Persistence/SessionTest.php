<?php

namespace Test\Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Persistence\Session;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSameSiteOptions;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class SessionTest
{
    private function configuration(): Session
    {
        return new Session(Fixture::node("session"));
    }

    public function getParameterName()
    {
        return (new Strings($this->configuration()->getParameterName()))->assertEquals("authentication");
    }

    public function getIsHttpOnly()
    {
        return (new Booleans($this->configuration()->getIsHttpOnly()))->assertTrue();
    }

    public function getIsHttpsOnly()
    {
        return (new Booleans($this->configuration()->getIsHttpsOnly()))->assertTrue();
    }

    public function getSameSite()
    {
        $actual = $this->configuration()->getSameSite();

        return (new Arrays([$actual]))->assertIdentical([CookieSameSiteOptions::STRICT]);
    }

    public function getHandler()
    {
        return (new Strings($this->configuration()->getHandler()))->assertEquals("ExampleHandler");
    }

    public function getExpirationTime()
    {
        return (new Integers($this->configuration()->getExpirationTime()))->assertEquals(1800);
    }
}
