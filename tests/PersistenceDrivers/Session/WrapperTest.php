<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers\Session;

use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Configuration\Persistence\Session;
use Lucinda\WebSecurity\PersistenceDrivers\Session\PersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Session\Wrapper;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class WrapperTest
{
    public function getDriver()
    {
        $configuration = new Session(Fixture::node("session-wrapper"));
        $driver = (new Wrapper($configuration, "127.0.0.1"))->getDriver();

        return (new Objects($driver))->assertInstanceOf(PersistenceDriver::class);
    }
}
