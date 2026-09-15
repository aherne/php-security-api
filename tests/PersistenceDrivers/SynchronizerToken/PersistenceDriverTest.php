<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\PersistenceDriver;

final class PersistenceDriverTest
{
    private function driver(): PersistenceDriver
    {
        return new PersistenceDriver("secret", "127.0.0.1", 3600, 60);
    }

    public function setAccessToken()
    {
        $driver = $this->driver();
        $driver->setAccessToken("incoming-token");

        return (new Strings($driver->getAccessToken()))->assertEquals("incoming-token");
    }

    public function getAccessToken()
    {
        $driver = $this->driver();
        $driver->setAccessToken("incoming-token");

        return (new Strings($driver->getAccessToken()))->assertEquals("incoming-token");
    }

    public function save()
    {
        $driver = $this->driver();
        $userInfo = new LoggedInUserInfo(7, AuthenticationStage::AUTHENTICATED);
        $driver->save($userInfo);

        return (new Strings($driver->getAccessToken()))->assertNotEmpty();
    }

    public function load()
    {
        $driver = $this->driver();
        $expected = new LoggedInUserInfo(7, AuthenticationStage::AUTHENTICATED);
        $driver->save($expected);
        $actual = $driver->load();

        return (new Arrays([$actual->getUserID(), $actual->getAuthenticatedStage()]))
            ->assertIdentical([7, AuthenticationStage::AUTHENTICATED]);
    }

    public function clear()
    {
        $driver = $this->driver();
        $driver->setAccessToken("incoming-token");
        $driver->clear();

        return (new Strings($driver->getAccessToken()))->assertEmpty();
    }
}
