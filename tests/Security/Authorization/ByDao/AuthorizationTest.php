<?php

namespace Test\Lucinda\WebSecurity\Security\Authorization\ByDao;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Security\Authorization\ByDao\Authorization;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authorization\PageAuthorizationDAO;
use Test\Lucinda\WebSecurity\mocks\Authorization\UserAuthorizationDAO;

final class AuthorizationTest
{
    public function authorize()
    {
        PageAuthorizationDAO::$pageID = 10;
        PageAuthorizationDAO::$public = true;
        $authorization = new Authorization("/forbidden", "/login");
        $result = $authorization->authorize("forum", null, new PageAuthorizationDAO(), new UserAuthorizationDAO(), "GET");

        return (new Arrays([$result->getStatus(), $result->getCallbackURI()]))
            ->assertIdentical([ResultStatus::OK, ""]);
    }
}
