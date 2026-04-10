<?php

namespace Test\Lucinda\WebSecurity\Authorization\XML;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Authorization\XML\UserAuthorizationXML;

class UserAuthorizationXMLTest
{
    public function getRoles()
    {
        $xml = \simplexml_load_string(
            '
<xml>
    <users roles="GUEST">
        <user id="1" roles="USER"/>
    </users>
</xml>
'
        );
        $object = new UserAuthorizationXML($xml);

        return [
            (new Arrays($object->getRoles(null)))->assertEquals(["GUEST"], "checks user without roles"),
            (new Arrays($object->getRoles(1)))->assertEquals(["USER"], "checks user without roles"),
        ];
    }
}
