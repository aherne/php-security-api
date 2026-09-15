<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken;

use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\PersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\Wrapper;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class WrapperTest
{
    public function getDriver()
    {
        $xml = Fixture::node("synchronizer-token-wrapper");
        $configuration = new \Lucinda\WebSecurity\Configuration\Persistence\SynchronizerToken($xml);
        $driver = (new Wrapper($configuration, "127.0.0.1"))->getDriver();

        return (new Objects($driver))->assertInstanceOf(PersistenceDriver::class);
    }
}
