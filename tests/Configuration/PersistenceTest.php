<?php

namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Arrays;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class PersistenceTest
{
    public function getDrivers()
    {
        $drivers = Fixture::configuration()->getPersistence()->getDrivers();

        return (new Arrays($drivers))->assertSize(1);
    }
}
