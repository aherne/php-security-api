<?php

namespace Test\Lucinda\WebSecurity\Authorization\XML;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Authorization\XML\PageAuthorizationXML;

class PageAuthorizationXMLTest
{
    public function getRoles()
    {
        $xml = \simplexml_load_string(
            '
<xml>
    <routes>
        <route id="login" roles="GUEST,USER"/>
        <route id="index" roles="USER"/>
        <route id="logout" roles="USER,ADMINISTRATOR"/>
        <route id="admin" roles="ADMINISTRATOR"/>
    </routes>
</xml>
'
        );
        $object = new PageAuthorizationXML($xml);

        return [
            (new Arrays($object->getRoles("asdf")))->assertEquals([], "checks route without roles"),
            (new Arrays($object->getRoles("login")))->assertEquals(["GUEST","USER"], "checks route without roles"),
        ];
    }
}
