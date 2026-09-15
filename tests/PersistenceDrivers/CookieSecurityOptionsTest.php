<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSameSiteOptions;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;

final class CookieSecurityOptionsTest
{
    private function options(): CookieSecurityOptions
    {
        $options = new CookieSecurityOptions();
        $options->setExpirationTime(1200);
        $options->setIsHttpOnly(true);
        $options->setIsSecure(true);
        $options->setSameSite(CookieSameSiteOptions::STRICT);

        return $options;
    }

    public function setExpirationTime()
    {
        return (new Integers($this->options()->getExpirationTime()))->assertEquals(1200);
    }

    public function getExpirationTime()
    {
        return $this->setExpirationTime();
    }

    public function setIsHttpOnly()
    {
        return (new Booleans($this->options()->isHttpOnly()))->assertTrue();
    }

    public function isHttpOnly()
    {
        return $this->setIsHttpOnly();
    }

    public function setIsSecure()
    {
        return (new Booleans($this->options()->isSecure()))->assertTrue();
    }

    public function isSecure()
    {
        return $this->setIsSecure();
    }

    public function setSameSite()
    {
        $actual = $this->options()->getSameSite();

        return (new Arrays([$actual]))->assertIdentical([CookieSameSiteOptions::STRICT]);
    }

    public function getSameSite()
    {
        return $this->setSameSite();
    }
}
