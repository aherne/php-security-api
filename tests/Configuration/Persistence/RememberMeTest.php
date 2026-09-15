<?php

namespace Test\Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Persistence\RememberMe;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSameSiteOptions;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class RememberMeTest
{
    private function configuration(): RememberMe
    {
        return new RememberMe(Fixture::node("remember-me"));
    }

    public function getParameterName()
    {
        return (new Strings($this->configuration()->getParameterName()))->assertEquals("remembered_user");
    }

    public function getSecret()
    {
        return (new Strings($this->configuration()->getSecret()))->assertEquals("secret");
    }

    public function getIsHttpOnly()
    {
        return (new Booleans($this->configuration()->getIsHttpOnly()))->assertTrue();
    }

    public function getIsHttpsOnly()
    {
        return (new Booleans($this->configuration()->getIsHttpsOnly()))->assertFalse();
    }

    public function getSameSite()
    {
        $actual = $this->configuration()->getSameSite();

        return (new Arrays([$actual]))->assertIdentical([CookieSameSiteOptions::LAX]);
    }

    public function getExpirationTime()
    {
        return (new Integers($this->configuration()->getExpirationTime()))->assertEquals(86400);
    }
}
