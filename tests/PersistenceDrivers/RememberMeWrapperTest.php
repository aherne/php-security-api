<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMeWrapper;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Integers;

class RememberMeWrapperTest
{
    private $xml;

    public function __construct()
    {
        $this->xml = \simplexml_load_string(
            '
<remember_me secret="'.(new SaltGenerator(10))->getSalt().'"/>
'
        );
    }

    public function getDriver()
    {
        $driver = new RememberMeWrapper($this->xml, "127.0.0.1");
        $driver->getDriver()->save(1);
        return (new Integers((int) $driver->getDriver()->load()))->assertEquals(1);
    }
}
