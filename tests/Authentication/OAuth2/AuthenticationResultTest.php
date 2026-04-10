<?php

namespace Test\Lucinda\WebSecurity\Authentication\OAuth2;

use Lucinda\WebSecurity\Authentication\OAuth2\AuthenticationResult;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\ResultStatus;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class AuthenticationResultTest
{
    private AuthenticationResult $object;

    public function __construct()
    {
        $this->object = new AuthenticationResult(ResultStatus::LOGIN_OK);
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


    public function getStatus()
    {
        return (new Strings($this->object->getStatus()->name))->assertEquals(ResultStatus::LOGIN_OK->name);
    }


    public function setCallbackURI()
    {
        $this->object->setCallbackURI("foo/bar");
        return (new Strings($this->object->getCallbackURI()))->assertEquals("foo/bar");
    }


    public function getCallbackURI()
    {
        return (new Strings($this->object->getCallbackURI()))->assertEquals("foo/bar");
    }


    public function setUserID()
    {
        $this->object->setUserID(1);
        return (new Integers((int) $this->object->getUserID()))->assertEquals(1);
    }


    public function getUserID()
    {
        return (new Integers((int) $this->object->getUserID()))->assertEquals(1);
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
