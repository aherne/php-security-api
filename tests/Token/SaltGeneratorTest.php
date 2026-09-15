<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Token\SaltGenerator;

final class SaltGeneratorTest
{
    public function getSalt()
    {
        $salt = (new SaltGenerator(32))->getSalt();

        return (new Strings($salt))->assertSize(32);
    }
}
