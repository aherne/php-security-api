<?php

namespace Test\Lucinda\WebSecurity;

use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\UserIdDetector;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver as RememberMePersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Session\PersistenceDriver as SessionPersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Token\JsonWebTokenPersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Validator\Integers;

class UserIdDetectorTest
{
    public function getUserID()
    {
        $results = [];

        $salt = (new SaltGenerator(12))->getSalt();

        $persistenceDriver = new RememberMePersistenceDriver($salt, "uid", new CookieSecurityOptions());
        $persistenceDriver->save(1);
        $detector = new UserIdDetector([$persistenceDriver]);
        $results[] = (new Integers((int) $detector->getUserID()))->assertEquals(1, "tested remember me");

        $persistenceDriver = new SessionPersistenceDriver("id", new CookieSecurityOptions());
        $persistenceDriver->save(1);
        $detector = new UserIdDetector([$persistenceDriver]);
        $results[] = (new Integers((int) $detector->getUserID()))->assertEquals(1, "tested session");

        $persistenceDriver = new SynchronizerTokenPersistenceDriver($salt, "127.0.0.1");
        $persistenceDriver->save(1);
        $detector = new UserIdDetector([$persistenceDriver], $persistenceDriver->getAccessToken());
        $results[] = (new Integers((int) $detector->getUserID()))->assertEquals(1, "tested synchronizer token");

        $persistenceDriver = new JsonWebTokenPersistenceDriver($salt);
        $persistenceDriver->save(1);
        $detector = new UserIdDetector([$persistenceDriver], $persistenceDriver->getAccessToken());
        $results[] = (new Integers((int) $detector->getUserID()))->assertEquals(1, "tested json web token");

        return $results;
    }
}
