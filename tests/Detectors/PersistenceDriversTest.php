<?php

namespace Test\Lucinda\WebSecurity\Detectors;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Detectors\PersistenceDrivers;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\PersistenceDriver;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class PersistenceDriversTest
{
    public function getPersistenceDrivers()
    {
        $detector = new PersistenceDrivers(Fixture::configuration()->getPersistence(), "127.0.0.1");
        $drivers = $detector->getPersistenceDrivers();

        return [
            (new Arrays($drivers))->assertSize(1),
            (new Objects($drivers[0]))->assertInstanceOf(PersistenceDriver::class)
        ];
    }
}
