<?php

namespace Test\Lucinda\WebSecurity\Authentication\OAuth2;

use Lucinda\WebSecurity\Authentication\OAuth2\Exception;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Strings;

class ExceptionTest
{
    private Exception $object;

    public function __construct()
    {
        $this->object = new Exception("asd");
    }

    public function setErrorCode()
    {
        $this->object->setErrorCode("some code");
        return (new Strings($this->object->getErrorCode()))->assertEquals("some code");
    }


    public function getErrorCode()
    {
        return (new Strings($this->object->getErrorCode()))->assertEquals("some code");
    }


    public function setErrorDescription()
    {
        $this->object->setErrorDescription("some description");
        return (new Strings($this->object->getErrorDescription()))->assertEquals("some description");
    }


    public function getErrorDescription()
    {
        return (new Strings($this->object->getErrorDescription()))->assertEquals("some description");
    }
}
