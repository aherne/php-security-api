<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Token\RegenerationException;

final class RegenerationExceptionTest
{
    public function setPayload()
    {
        $exception = new RegenerationException();
        $exception->setPayload(["user" => 7]);

        return (new Arrays($exception->getPayload()))->assertIdentical(["user" => 7]);
    }

    public function getPayload()
    {
        return $this->setPayload();
    }
}
