<?php
namespace Test\Lucinda\WebSecurity\PersistenceDrivers\RememberMe;

use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Configuration\Persistence\RememberMe;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\Wrapper;

class WrapperTest
{
    public function getDriver()
    {
        $configuration = new RememberMe(
            simplexml_load_string('<remember_me secret="abcdefghijklmnopqrstuvwxyz123456"/>')
        );
        $wrapper = new Wrapper($configuration, "127.0.0.1");

        return (new Objects($wrapper->getDriver()))->assertInstanceOf(PersistenceDriver::class);
    }
}
