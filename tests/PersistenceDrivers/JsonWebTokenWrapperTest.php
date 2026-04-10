<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\WebSecurity\PersistenceDrivers\JsonWebTokenWrapper;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;

class JsonWebTokenWrapperTest
{
    private \SimpleXMLElement $xml;

    public function __construct()
    {
        $this->xml = \simplexml_load_string(
            '
<json_web_token secret="'.(new SaltGenerator(10))->getSalt().'" expiration="2" regeneration="1"/>
'
        );
    }

    public function getDriver()
    {
        $results = [];
        $driver = new JsonWebTokenWrapper($this->xml, "127.0.0.1");
        $driver->getDriver()->save(1);
        $results[] = (new Integers((int) $driver->getDriver()->load()))->assertEquals(1);
        sleep(1);
        $results[] = (new Integers((int) $driver->getDriver()->load()))->assertEquals(1);
        sleep(2);
        $results[] = (new Booleans($driver->getDriver()->load() === null))->assertTrue();
        return $results;
    }
}
