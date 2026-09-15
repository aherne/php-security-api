<?php

namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Configuration\RolesDetector;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class RolesDetectorTest
{
    public function getRoles()
    {
        $xml = Fixture::node("routes");
        $detector = new RolesDetector($xml, "routes", "route", "id");
        $roles = $detector->getRoles("admin");

        return (new Arrays($roles))->assertIdentical(["ADMIN", "EDITOR"]);
    }
}
