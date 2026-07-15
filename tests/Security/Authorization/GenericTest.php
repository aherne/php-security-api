<?php
namespace Test\Lucinda\WebSecurity\Security\Authorization;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Security\Authorization\Generic;
use Lucinda\WebSecurity\Security\Authorization\Result;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;

class GenericTest
{
    public function getResult()
    {
        $generic = new Generic();
        $result = new Result(ResultStatus::OK, "");

        $method = new \ReflectionMethod(Generic::class, "setResult");
        $method->invoke($generic, $result);

        return (new Booleans($generic->getResult() === $result))->assertTrue();
    }
}

