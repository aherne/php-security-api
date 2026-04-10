<?php

namespace Test\Lucinda\WebSecurity\Authentication\XML;

use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\ResultStatus;
use Lucinda\WebSecurity\Authentication\XML\Authentication;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class AuthenticationTest
{
    private $xml;
    private $persistenceDriver;

    public function __construct()
    {
        $this->xml = simplexml_load_string(
            '
<security>
    <users>
        <user id="1" username="test" password="'.password_hash("me", PASSWORD_BCRYPT).'"/>
    </users>
</security>'
        );
        $this->persistenceDriver = new SynchronizerTokenPersistenceDriver((new SaltGenerator(10))->getSalt(), "127.0.0.1");
    }

    public function login()
    {
        $results = [];
        $object = new Authentication($this->xml, [$this->persistenceDriver]);
        $results[] = (new Strings($object->login("test", "m1e")->getStatus()->name))->assertEquals(ResultStatus::LOGIN_FAILED->name, "tested failed login");
        $results[] = (new Strings($object->login("test", "me")->getStatus()->name))->assertEquals(ResultStatus::LOGIN_OK->name, "tested successful login");
        $results[] = (new Integers((int) $this->persistenceDriver->load()))->assertEquals(1, "tested login persistence");
        return $results;
    }


    public function logout()
    {
        $object = new Authentication($this->xml, [$this->persistenceDriver]);
        $results = [];
        $results[] = (new Strings($object->logout()->getStatus()->name))->assertEquals(ResultStatus::LOGOUT_OK->name, "tested successful logout");
        $results[] = (new Booleans($this->persistenceDriver->load() === null))->assertTrue("tested logout persistence");
        $results[] = (new Strings($object->logout()->getStatus()->name))->assertEquals(ResultStatus::LOGOUT_FAILED->name, "tested failed logout");
        return $results;
    }
}
