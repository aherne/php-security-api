<?php

namespace Test\Lucinda\WebSecurity\Security\Authorization;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Configuration\Authorization\ByXML as Configuration;
use Lucinda\WebSecurity\Configuration\RolesDetector;
use Lucinda\WebSecurity\Security\Authorization\ByXML;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authorization\UserRolesDAO;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class ByXMLTest
{
    public function getResult()
    {
        UserRolesDAO::$roles = ["USER"];
        $configuration = new Configuration(Fixture::node("authorization-xml"));
        $xml = Fixture::node("routes");
        $roles = new RolesDetector($xml, "routes", "route", "id");
        $result = (new ByXML($configuration, Fixture::request("forum"), 7, $roles))->getResult();

        return (new Arrays([$result->getStatus()]))->assertIdentical([ResultStatus::OK]);
    }
}
