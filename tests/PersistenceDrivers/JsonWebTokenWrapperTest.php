<?php
namespace Test\Lucinda\WebSecurity\PersistenceDrivers;
    
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\WebSecurity\PersistenceDrivers\JsonWebTokenWrapper;
use Lucinda\UnitTest\Result;

class JsonWebTokenWrapperTest
{
    private $xml;
    
    public function __construct()
    {
        $this->xml = \simplexml_load_string('
<json_web_token secret="'.(new SaltGenerator(10))->getSalt().'" expiration="2" regeneration="1"/>
');
    }

    public function getDriver()
    {
        $results = [];
        $driver = new JsonWebTokenWrapper($this->xml, "127.0.0.1");
        $driver->getDriver()->save(1);
        $results[] = new Result($driver->getDriver()->load()==1);
        sleep(1);
        $results[] = new Result($driver->getDriver()->load()==1);
        sleep(2);
        $results[] = new Result(!$driver->getDriver()->load());
        return $results;
    }
        

}
