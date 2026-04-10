<?php

namespace Test\Lucinda\WebSecurity\Authorization;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Authorization\Result as AuthorizationResult;
use Lucinda\WebSecurity\Authorization\ResultStatus;

class ResultTest
{
    private AuthorizationResult $object;

    public function __construct()
    {
        $this->object = new AuthorizationResult(ResultStatus::FORBIDDEN, "index");
    }

    public function getStatus()
    {
        return (new Strings($this->object->getStatus()->name))->assertEquals(ResultStatus::FORBIDDEN->name);
    }

    public function getCallbackURI()
    {
        return (new Strings($this->object->getCallbackURI()))->assertEquals("index");
    }
}
