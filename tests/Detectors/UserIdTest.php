<?php
namespace Test\Lucinda\WebSecurity\Detectors;

use Lucinda\UnitTest\Validator\Integers;
use Lucinda\WebSecurity\Detectors\UserId;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\PersistenceDriver;

class UserIdTest
{
    public function getUserID()
    {
        $emptyDriver = new PersistenceDriver("abcdefghijklmnopqrstuvwxyz123456", "127.0.0.1");
        $userDriver = new PersistenceDriver("abcdefghijklmnopqrstuvwxyz123456", "127.0.0.1");
        $userDriver->save(27);

        $detector = new UserId([$emptyDriver, $userDriver]);
        return (new Integers((int) $detector->getUserID()))->assertEquals(27);
    }
}
