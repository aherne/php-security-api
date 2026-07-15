<?php
namespace Test\Lucinda\WebSecurity\PersistenceDrivers\Session;

use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Configuration\Persistence\Session;
use Lucinda\WebSecurity\PersistenceDrivers\Session\PersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Session\Wrapper;

class WrapperTest
{
    public function getDriver()
    {
        $configuration = new Session(simplexml_load_string('<session parameter_name="sid"/>'));
        $wrapper = new Wrapper($configuration, "127.0.0.1");

        return (new Objects($wrapper->getDriver()))->assertInstanceOf(PersistenceDriver::class);
    }
}
