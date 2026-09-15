<?php

namespace Test\Lucinda\WebSecurity\Security;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Security\Authorization;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authorization\PageAuthorizationDAO;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class AuthorizationTest
{
    public function getOutcome()
    {
        PageAuthorizationDAO::$pageID = 10;
        PageAuthorizationDAO::$public = true;
        $configuration = Fixture::configuration()->getAuthorization();
        $outcome = (new Authorization($configuration, Fixture::request("forum"), null))->getOutcome();

        return (new Arrays([$outcome->getStatus()]))->assertIdentical([ResultStatus::OK]);
    }
}
