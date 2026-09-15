<?php

namespace Test\Lucinda\WebSecurity\Security\Authorization;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Security\Authorization\ByDao;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authorization\PageAuthorizationDAO;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class ByDaoTest
{
    public function getResult()
    {
        PageAuthorizationDAO::$pageID = 10;
        PageAuthorizationDAO::$public = true;
        $configuration = Fixture::configuration()->getAuthorization()->getMethods()[0];
        $result = (new ByDao($configuration, Fixture::request("forum"), null))->getResult();

        return (new Arrays([$result->getStatus()]))->assertIdentical([ResultStatus::OK]);
    }
}
