<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSameSiteOptions;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;

class CookieSecurityOptionsTest
{
    private CookieSecurityOptions $options;

    public function __construct()
    {
        $this->options = new CookieSecurityOptions();
    }

    public function setExpirationTime()
    {
        $this->options->setExpirationTime(1);
        return (new Integers($this->options->getExpirationTime()))->assertEquals(1, "tested via getExpirationTime()");
    }

    public function getExpirationTime()
    {
        return (new Integers($this->options->getExpirationTime()))->assertEquals(1);
    }


    public function setIsHttpOnly()
    {
        $this->options->setIsHttpOnly(true);
        return (new Booleans($this->options->isHttpOnly()))->assertTrue("tested via isHttpOnly()");
    }


    public function isHttpOnly()
    {
        return (new Booleans($this->options->isHttpOnly()))->assertTrue();
    }


    public function setIsSecure()
    {
        $this->options->setIsSecure(true);
        return (new Booleans($this->options->isSecure()))->assertTrue("tested via isSecure()");
    }


    public function isSecure()
    {
        return (new Booleans($this->options->isSecure()))->assertTrue();
    }
    public function setSameSite()
    {
        $this->options->setSameSite(CookieSameSiteOptions::STRICT);
        return (new Strings($this->options->getSameSite()->name))->assertEquals(CookieSameSiteOptions::STRICT->name, "tested via getSameSite()");
    }
        

    public function getSameSite()
    {
        return (new Strings($this->options->getSameSite()->name))->assertEquals(CookieSameSiteOptions::STRICT->name);
    }
        

}
