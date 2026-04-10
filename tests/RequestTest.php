<?php

namespace Test\Lucinda\WebSecurity;

use Lucinda\WebSecurity\Request;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Strings;

class RequestTest
{
    private Request $object;

    public function __construct()
    {
        $this->object = new Request();
    }


    public function setUri()
    {
        $this->object->setUri("login");
        return (new Strings($this->object->getUri()))->assertEquals("login");
    }


    public function setContextPath()
    {
        $this->object->setContextPath("test");
        return (new Strings($this->object->getContextPath()))->assertEquals("test");
    }


    public function setIpAddress()
    {
        $this->object->setIpAddress("127.0.0.1");
        return (new Strings($this->object->getIpAddress()))->assertEquals("127.0.0.1");
    }


    public function setMethod()
    {
        $this->object->setMethod("POST");
        return (new Strings($this->object->getMethod()))->assertEquals("POST");
    }


    public function setParameters()
    {
        $this->object->setParameters(["username"=>"test", "password"=>"me"]);
        return (new Arrays($this->object->getParameters()))->assertEquals(["username"=>"test", "password"=>"me"]);
    }


    public function setAccessToken()
    {
        $this->object->setAccessToken("qwerty");
        return (new Strings($this->object->getAccessToken()))->assertEquals("qwerty");
    }

    public function getUri()
    {
        return (new Strings($this->object->getUri()))->assertEquals("login");
    }


    public function getContextPath()
    {
        return (new Strings($this->object->getContextPath()))->assertEquals("test");
    }


    public function getIpAddress()
    {
        return (new Strings($this->object->getIpAddress()))->assertEquals("127.0.0.1");
    }


    public function getMethod()
    {
        return (new Strings($this->object->getMethod()))->assertEquals("POST");
    }


    public function getParameters()
    {
        return (new Arrays($this->object->getParameters()))->assertEquals(["username"=>"test", "password"=>"me"]);
    }


    public function getAccessToken()
    {
        return (new Strings($this->object->getAccessToken()))->assertEquals("qwerty");
    }
}
