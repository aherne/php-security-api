<?php

namespace Test\Lucinda\WebSecurity;

use Lucinda\WebSecurity\PersistenceDriversDetector;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver as RememberMePersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Session\PersistenceDriver as SessionPersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Token\JsonWebTokenPersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;

class PersistenceDriversDetectorTest
{
    private $xml;

    public function __construct()
    {
        $salt = (new SaltGenerator(10))->getSalt();
        $this->xml = \simplexml_load_string(
            '
<security>
    <persistence>
        <session/>
        <remember_me secret="'.$salt.'"/>
        <synchronizer_token secret="'.$salt.'"/>
        <json_web_token secret="'.$salt.'"/>
    </persistence>
</security>
'
        );
    }

    public function getPersistenceDrivers()
    {
        $pdd = new PersistenceDriversDetector($this->xml, "127,0.0.1");
        $persistenceDrivers = $pdd->getPersistenceDrivers();
        $results = [];
        $results[] = (new Objects($persistenceDrivers[0]))->assertInstanceOf(SessionPersistenceDriver::class, "tested session");
        $results[] = (new Objects($persistenceDrivers[1]))->assertInstanceOf(RememberMePersistenceDriver::class, "tested remember me");
        $results[] = (new Objects($persistenceDrivers[2]))->assertInstanceOf(SynchronizerTokenPersistenceDriver::class, "tested synchronizer token");
        $results[] = (new Objects($persistenceDrivers[3]))->assertInstanceOf(JsonWebTokenPersistenceDriver::class, "tested json web token");
        return $results;
    }
}
