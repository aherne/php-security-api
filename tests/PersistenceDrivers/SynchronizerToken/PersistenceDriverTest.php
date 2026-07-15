<?php
namespace Test\Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\PersistenceDriver;

class PersistenceDriverTest
{
    private PersistenceDriver $driver;

    public function __construct()
    {
        $this->driver = new PersistenceDriver(
            "abcdefghijklmnopqrstuvwxyz123456",
            "127.0.0.1",
            3600,
            60
        );
    }

    public function setAccessToken()
    {
        $this->driver->setAccessToken("token");
        return (new Strings($this->driver->getAccessToken() ?? ""))->assertEquals("token");
    }

    public function getAccessToken()
    {
        $driver = new PersistenceDriver("abcdefghijklmnopqrstuvwxyz123456", "127.0.0.1");
        return (new Booleans($driver->getAccessToken() === null))->assertTrue();
    }

    public function save()
    {
        $this->driver->save(15);
        return (new Strings($this->driver->getAccessToken() ?? ""))->assertNotEmpty();
    }

    public function load()
    {
        $this->driver->save(15);
        return (new Integers((int) $this->driver->load()))->assertEquals(15);
    }

    public function clear()
    {
        $this->driver->save(15);
        $this->driver->clear();
        return (new Booleans($this->driver->load() === null))->assertTrue();
    }
}
