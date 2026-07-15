<?php
namespace Test\Lucinda\WebSecurity\Detectors;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Configuration\Persistence;
use Lucinda\WebSecurity\Detectors\PersistenceDrivers;

class PersistenceDriversTest
{
    public function getPersistenceDrivers()
    {
        $configuration = new Persistence(simplexml_load_string('
            <xml><persistence>
                <session/>
                <remember_me secret="abcdefghijklmnopqrstuvwxyz123456"/>
                <synchronizer_token secret="abcdefghijklmnopqrstuvwxyz123456"/>
            </persistence></xml>
        '));
        $detector = new PersistenceDrivers($configuration, "127.0.0.1");

        return (new Arrays($detector->getPersistenceDrivers()))->assertSize(3);
    }
}

