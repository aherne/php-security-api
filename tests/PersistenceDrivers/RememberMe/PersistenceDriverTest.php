<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers\RememberMe;

use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;

class PersistenceDriverTest
{
    private PersistenceDriver $object;

    public function __construct()
    {
        $securityOptions = new CookieSecurityOptions();
        $securityOptions->setExpirationTime(3600);
        $this->object = new PersistenceDriver(
            (new SaltGenerator(10))->getSalt(),
            "remember_me",
            $securityOptions,
            "192.168.1.9"
        );
    }

    public function save()
    {
        $this->object->save(1);
        return (new Integers((int) $this->object->load()))->assertEquals(1);
    }

    public function load()
    {
        return (new Integers((int) $this->object->load()))->assertEquals(1);
    }


    public function clear()
    {
        $this->object->clear();
        return (new Booleans($this->object->load() === null))->assertTrue();
    }
}
