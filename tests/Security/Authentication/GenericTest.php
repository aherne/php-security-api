<?php
namespace Test\Lucinda\WebSecurity\Security\Authentication;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Security\Authentication\Generic;

class GenericTest
{
    public function getOutcome()
    {
        return (new Booleans((new Generic())->getOutcome() === null))->assertTrue();
    }
}

