<?php
namespace Test\Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken;

use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Configuration\Persistence\SynchronizerToken;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\PersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\Wrapper;

class WrapperTest
{
    public function getDriver()
    {
        $configuration = new SynchronizerToken(
            simplexml_load_string('<synchronizer_token secret="abcdefghijklmnopqrstuvwxyz123456"/>')
        );
        $wrapper = new Wrapper($configuration, "127.0.0.1");

        return (new Objects($wrapper->getDriver()))->assertInstanceOf(PersistenceDriver::class);
    }
}
