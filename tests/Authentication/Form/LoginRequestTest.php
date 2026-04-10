<?php

namespace Test\Lucinda\WebSecurity\Authentication\Form;

use Lucinda\WebSecurity\Authentication\Form\LoginRequest;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Strings;

class LoginRequestTest
{
    private LoginRequest $object;

    public function __construct()
    {
        $this->object = new LoginRequest();
    }

    public function setUsername()
    {
        $this->object->setUsername("test");
        return (new Strings($this->object->getUsername()))->assertEquals("test");
    }


    public function setPassword()
    {
        $this->object->setPassword("me");
        return (new Strings($this->object->getPassword()))->assertEquals("me");
    }


    public function setRememberMe()
    {
        $this->object->setRememberMe(true);
        return (new Booleans($this->object->isRememberMe()))->assertTrue();
    }


    public function setSourcePage()
    {
        $this->object->setSourcePage("login");
        return (new Strings($this->object->getSourcePage()))->assertEquals("login");
    }


    public function setDestinationPage()
    {
        $this->object->setDestinationPage("index");
        return (new Strings($this->object->getDestinationPage()))->assertEquals("index");
    }


    public function getUsername()
    {
        return (new Strings($this->object->getUsername()))->assertEquals("test");
    }


    public function getPassword()
    {
        return (new Strings($this->object->getPassword()))->assertEquals("me");
    }


    public function isRememberMe()
    {
        return (new Booleans($this->object->isRememberMe()))->assertTrue();
    }


    public function getSourcePage()
    {
        return (new Strings($this->object->getSourcePage()))->assertEquals("login");
    }


    public function getDestinationPage()
    {
        return (new Strings($this->object->getDestinationPage()))->assertEquals("index");
    }
}
