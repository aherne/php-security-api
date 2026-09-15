<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers\RememberMe;

use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Configuration\Persistence\RememberMe;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\Wrapper;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class WrapperTest
{
    public function getDriver()
    {
        $configuration = new RememberMe(Fixture::node("remember-me-wrapper"));
        $driver = (new Wrapper($configuration, "127.0.0.1"))->getDriver();

        return (new Objects($driver))->assertInstanceOf(PersistenceDriver::class);
    }
}
