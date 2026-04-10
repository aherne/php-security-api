<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Strings;

class SaltGeneratorTest
{
    public function getSalt()
    {
        $object = new SaltGenerator(12);
        return (new Strings($object->getSalt()))->assertSize(12);
    }
}
