<?php

namespace Test\Lucinda\WebSecurity\Authorization\XML;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Authorization\XML\RolesDetector;

class RolesDetectorTest
{
    public function getRoles()
    {
        $xml = \simplexml_load_string(
            '
<xml>
    <routes roles="USER">
        <route id="login" roles="GUEST,USER"/>
        <route id="index" roles="USER"/>
        <route id="logout" roles="USER,ADMINISTRATOR"/>
        <route id="admin" roles="ADMINISTRATOR"/>
    </routes>
</xml>
'
        );

        $object = new RolesDetector($xml, "routes", "route", "id", "asdf");
        $result1 = (new Arrays($object->getRoles()))->assertEquals([], "checks element without roles");

        $object = new RolesDetector($xml, "routes", "route", "id", "login");
        $result2 = (new Arrays($object->getRoles("login")))->assertEquals(["GUEST","USER"], "checks element without roles");

        return [$result1, $result2];
    }
}
