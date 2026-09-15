<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers\RememberMe;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver;

final class PersistenceDriverTest
{
    private const COOKIE_NAME = "security_test_remember_me";

    private function driver(): PersistenceDriver
    {
        $options = new CookieSecurityOptions();
        $options->setExpirationTime(3600);

        return new PersistenceDriver("secret", self::COOKIE_NAME, $options, "127.0.0.1");
    }

    public function save()
    {
        unset($_COOKIE[self::COOKIE_NAME]);
        $driver = $this->driver();
        $driver->save(new LoggedInUserInfo(7, AuthenticationStage::AUTHENTICATED));

        return (new Arrays($_COOKIE))->assertContainsKey(self::COOKIE_NAME);
    }

    public function load()
    {
        $driver = $this->driver();
        $driver->save(new LoggedInUserInfo(7, AuthenticationStage::AUTHENTICATED));
        $actual = $driver->load();

        return (new Arrays([$actual->getUserID(), $actual->getAuthenticatedStage()]))
            ->assertIdentical([7, AuthenticationStage::AUTHENTICATED]);
    }

    public function clear()
    {
        $driver = $this->driver();
        $driver->save(new LoggedInUserInfo(7, AuthenticationStage::AUTHENTICATED));
        $driver->clear();
        $cookieExists = array_key_exists(self::COOKIE_NAME, $_COOKIE);

        return (new Booleans($cookieExists))->assertFalse();
    }
}
