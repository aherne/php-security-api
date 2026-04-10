<?php

namespace Test\Lucinda\WebSecurity;

use Lucinda\WebSecurity\CsrfTokenDetector;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Strings;

class CsrfTokenDetectorTest
{
    private $xml;

    public function __construct()
    {
        $this->xml = \simplexml_load_string(
            '
<security>
    <csrf secret="'.(new SaltGenerator(10))->getSalt().'"/>
</security>
'
        );
    }

    public function generate()
    {
        $object = new CsrfTokenDetector($this->xml, "127.0.0.1");
        return (new Strings($object->generate(0)))->assertSize(180);
    }


    public function isValid()
    {
        $userID = 0;
        $object = new CsrfTokenDetector($this->xml, "127.0.0.1");
        $token = $object->generate($userID);
        return (new Booleans($object->isValid($token, $userID)))->assertTrue();
    }
}
