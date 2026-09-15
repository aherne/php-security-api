<?php

namespace Test\Lucinda\WebSecurity\Wrapper;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Wrapper\Authorization;
use Test\Lucinda\WebSecurity\mocks\Authorization\PageAuthorizationDAO;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class AuthorizationTest
{
    public function run()
    {
        PageAuthorizationDAO::$pageID = 10;
        PageAuthorizationDAO::$public = true;
        $authorization = new Authorization(Fixture::configuration(), Fixture::request("forum"));
        $outcome = $authorization->run();

        return (new Arrays([$outcome]))->assertIdentical([null]);
    }
}
