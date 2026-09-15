<?php

namespace Test\Lucinda\WebSecurity\Security\Authorization\ByXML;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Configuration\RolesDetector;
use Lucinda\WebSecurity\Security\Authorization\ByXML\Authorization;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authorization\UserRolesDAO;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class AuthorizationTest
{
    public function authorize()
    {
        UserRolesDAO::$roles = ["USER"];
        $xml = Fixture::node("routes");
        $roles = new RolesDetector($xml, "routes", "route", "id");
        $authorization = new Authorization("/forbidden", "/login");
        $result = $authorization->authorize($roles, "forum", 7, new UserRolesDAO());

        return (new Arrays([$result->getStatus()]))->assertIdentical([ResultStatus::OK]);
    }
}
