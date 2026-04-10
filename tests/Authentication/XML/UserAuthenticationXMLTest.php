<?php

namespace Test\Lucinda\WebSecurity\Authentication\XML;

use Lucinda\WebSecurity\Authentication\XML\UserAuthenticationXML;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;

class UserAuthenticationXMLTest
{
    public function login()
    {
        $xml = simplexml_load_string(
            '
<security>
    <users>
        <user id="1" username="test" password="'.password_hash("me", PASSWORD_BCRYPT).'"/>
    </users>
</security>'
        );
        $object = new UserAuthenticationXML($xml);

        $results = [];
        $results[] = (new Booleans($object->login("test", "me1") === null))->assertTrue("tested failed login");
        $results[] = (new Integers((int) $object->login("test", "me")))->assertEquals(1, "tested successful login");
        return $results;
    }
}
