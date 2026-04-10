<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers\Token;

use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class SynchronizerTokenPersistenceDriverTest
{
    private SynchronizerTokenPersistenceDriver $object;
    private string $salt;

    public function __construct()
    {
        $this->salt = (new SaltGenerator(10))->getSalt();
        $this->object = new SynchronizerTokenPersistenceDriver($this->salt, "127.0.0.1");
    }

    public function save()
    {
        $this->object->save(1);
        return (new Integers((int) $this->object->load()))->assertEquals(1);
    }

    public function load()
    {
        return (new Integers((int) $this->object->load()))->assertEquals(1);
    }


    public function clear()
    {
        $this->object->clear();
        return (new Booleans($this->object->load() === null))->assertTrue();
    }


    public function setAccessToken()
    {
        $this->object->setAccessToken("qwerty");
        return (new Strings($this->object->getAccessToken()))->assertEquals("qwerty");
    }


    public function getAccessToken()
    {
        return (new Strings($this->object->getAccessToken()))->assertEquals("qwerty");
    }
}
