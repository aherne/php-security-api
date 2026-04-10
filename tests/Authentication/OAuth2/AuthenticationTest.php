<?php

namespace Test\Lucinda\WebSecurity\Authentication\OAuth2;

use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\WebSecurity\Authentication\OAuth2\Authentication;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockVendorAuthenticationDAO;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockOauth2Driver;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\ResultStatus;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class AuthenticationTest
{
    private $dao;
    private $persistenceDriver;

    public function __construct()
    {
        $this->dao = new MockVendorAuthenticationDAO();
        $this->persistenceDriver = new SynchronizerTokenPersistenceDriver((new SaltGenerator(10))->getSalt(), "127.0.0.1");
    }

    public function login()
    {
        $results = [];
        $object = new Authentication($this->dao, [$this->persistenceDriver]);
        $results[] = (new Strings($object->login(new MockOauth2Driver("Google"), "qwerty")->getStatus()->name))->assertEquals(ResultStatus::LOGIN_FAILED->name, "tested failed login");
        $results[] = (new Strings($object->login(new MockOauth2Driver("Facebook"), "qwerty")->getStatus()->name))->assertEquals(ResultStatus::LOGIN_OK->name, "tested successful login");
        $results[] = (new Strings($object->login(new MockOauth2Driver("Facebook"), "qwerty")->getAccessToken()))->assertEquals("asdfgh", "tested access token");
        $results[] = (new Integers((int) $this->persistenceDriver->load()))->assertEquals(1, "tested login persistence");
        return $results;
    }


    public function logout()
    {
        $results = [];
        $object = new Authentication($this->dao, [$this->persistenceDriver]);
        $results[] = (new Strings($object->logout()->getStatus()->name))->assertEquals(ResultStatus::LOGOUT_OK->name, "tested successful logout");
        $results[] = (new Booleans($this->persistenceDriver->load() === null))->assertTrue("tested logout persistence");
        $results[] = (new Strings($object->logout()->getStatus()->name))->assertEquals(ResultStatus::LOGOUT_FAILED->name, "tested failed logout");
        return $results;
    }
}
