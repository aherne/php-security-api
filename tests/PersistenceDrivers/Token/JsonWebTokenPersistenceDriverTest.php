<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers\Token;

use Lucinda\WebSecurity\PersistenceDrivers\Token\JsonWebTokenPersistenceDriver;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class JsonWebTokenPersistenceDriverTest
{
    private JsonWebTokenPersistenceDriver $object;

    public function __construct()
    {
        $this->object = new JsonWebTokenPersistenceDriver((new SaltGenerator(10))->getSalt());
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
