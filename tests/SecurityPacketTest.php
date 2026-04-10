<?php

namespace Test\Lucinda\WebSecurity;

use Lucinda\WebSecurity\SecurityPacket;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\ResultStatus;
use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class SecurityPacketTest
{
    private SecurityPacket $object;

    public function __construct()
    {
        $this->object = new SecurityPacket("test");
    }

    public function setCallback()
    {
        $this->object->setCallback("index");
        return (new Strings($this->object->getCallback()))->assertEquals("index");
    }


    public function getCallback()
    {
        return (new Strings($this->object->getCallback()))->assertEquals("index");
    }


    public function setStatus()
    {
        $this->object->setStatus(ResultStatus::LOGIN_OK);
        return (new Strings($this->object->getStatus()))->assertEquals("login_ok");
    }


    public function getStatus()
    {
        return (new Strings($this->object->getStatus()))->assertEquals("login_ok");
    }


    public function setAccessToken()
    {
        $persistenceDriver = new SynchronizerTokenPersistenceDriver((new SaltGenerator(10))->getSalt(), "127.0.0.1");
        $persistenceDriver->save(1);
        $this->object->setAccessToken(1, [$persistenceDriver]);
        return (new Strings($this->object->getAccessToken() ?? ""))->assertNotEmpty();
    }


    public function getAccessToken()
    {
        return (new Strings($this->object->getAccessToken() ?? ""))->assertNotEmpty();
    }


    public function setTimePenalty()
    {
        $this->object->setTimePenalty(1);
        return (new Integers($this->object->getTimePenalty()))->assertEquals(1);
    }


    public function getTimePenalty()
    {
        return (new Integers($this->object->getTimePenalty()))->assertEquals(1);
    }
}
