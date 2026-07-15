<?php
namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Configuration\Persistence;

class PersistenceTest
{
    public function getDrivers()
    {
        $object = new Persistence(\simplexml_load_string('
        <security>
                <persistence><synchronizer_token secret="12345678"/></persistence>
        </security>
        '));
        return (new Arrays($object->getDrivers()))->assertNotEmpty();
    }
        

}
