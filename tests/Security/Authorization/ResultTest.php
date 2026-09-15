<?php

namespace Test\Lucinda\WebSecurity\Security\Authorization;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Security\Authorization\Result;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;

final class ResultTest
{
    public function getStatus()
    {
        $result = new Result(ResultStatus::FORBIDDEN, "/forbidden");

        return (new Arrays([$result->getStatus()]))->assertIdentical([ResultStatus::FORBIDDEN]);
    }

    public function getCallbackURI()
    {
        $result = new Result(ResultStatus::FORBIDDEN, "/forbidden");

        return (new Strings($result->getCallbackURI()))->assertEquals("/forbidden");
    }
}
