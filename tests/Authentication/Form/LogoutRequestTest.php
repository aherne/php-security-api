<?php

namespace Test\Lucinda\WebSecurity\Authentication\Form;

use Lucinda\WebSecurity\Authentication\Form\LogoutRequest;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Strings;

class LogoutRequestTest
{
    private LogoutRequest $object;

    public function __construct()
    {
        $this->object = new LogoutRequest();
    }

    public function setSourcePage()
    {
        $this->object->setSourcePage("logout");
        return (new Strings($this->object->getSourcePage()))->assertEquals("logout");
    }


    public function setDestinationPage()
    {
        $this->object->setDestinationPage("index");
        return (new Strings($this->object->getDestinationPage()))->assertEquals("index");
    }


    public function getSourcePage()
    {
        return (new Strings($this->object->getSourcePage()))->assertEquals("logout");
    }


    public function getDestinationPage()
    {
        return (new Strings($this->object->getDestinationPage()))->assertEquals("index");
    }
}
