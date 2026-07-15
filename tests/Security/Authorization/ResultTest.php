<?php
namespace Test\Lucinda\WebSecurity\Security\Authorization;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Security\Authorization\Result;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;

class ResultTest
{
    private function result(): Result
    {
        return new Result(ResultStatus::FORBIDDEN, "forbidden");
    }

    public function getStatus()
    {
        return (new Booleans($this->result()->getStatus() === ResultStatus::FORBIDDEN))->assertTrue();
    }

    public function getCallbackURI()
    {
        return (new Strings($this->result()->getCallbackURI()))->assertEquals("forbidden");
    }
}

