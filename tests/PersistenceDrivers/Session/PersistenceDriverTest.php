<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers\Session;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\PersistenceDrivers\Session\PersistenceDriver;

final class PersistenceDriverTest
{
    private const SESSION_KEY = "security_test_user";

    private function driver(): PersistenceDriver
    {
        $options = new CookieSecurityOptions();
        $options->setExpirationTime(3600);

        return new PersistenceDriver(self::SESSION_KEY, $options, "127.0.0.1");
    }

    private function startSession(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
    }

    public function save()
    {
        $this->startSession();
        $driver = $this->driver();
        $driver->save(new LoggedInUserInfo(7, AuthenticationStage::AUTHENTICATED));

        return (new Arrays($_SESSION))->assertContainsKey(self::SESSION_KEY);
    }

    public function load()
    {
        $this->startSession();
        $driver = $this->driver();
        $driver->save(new LoggedInUserInfo(7, AuthenticationStage::AUTHENTICATED));
        $actual = $driver->load();

        return (new Arrays([$actual->getUserID(), $actual->getAuthenticatedStage()]))
            ->assertIdentical([7, AuthenticationStage::AUTHENTICATED]);
    }

    public function clear()
    {
        $this->startSession();
        $_SESSION["application_data"] = "value";
        $this->driver()->clear();

        return (new Arrays($_SESSION))->assertEmpty();
    }
}
