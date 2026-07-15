<?php
namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Configuration\Exception;
use Lucinda\WebSecurity\Configuration\RolesDetector;

class RolesDetectorTest
{
    public function getRoles(): array
    {
        $xml = simplexml_load_string('<xml><routes><route id="home" roles="USER, ADMIN"/></routes></xml>');
        $detector = new RolesDetector($xml, "routes", "route", "id", "home");

        try {
            new RolesDetector(
                simplexml_load_string('<xml><routes><route id="broken"/></routes></xml>'),
                "routes",
                "route",
                "id",
                "broken"
            );
            $exceptionResult = (new \Lucinda\UnitTest\Validator\Booleans(false))->assertTrue();
        } catch (Exception $exception) {
            $exceptionResult = (new Objects($exception))->assertInstanceOf(Exception::class);
        }

        return [
            (new Arrays($detector->getRoles()))->assertEquals(["USER", "ADMIN"]),
            (new Arrays((new RolesDetector($xml, "routes", "route", "id", "missing"))->getRoles()))->assertEmpty(),
            $exceptionResult
        ];
    }
}

