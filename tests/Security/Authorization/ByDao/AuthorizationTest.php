<?php
namespace Test\Lucinda\WebSecurity\Security\Authorization\ByDao;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Security\Authorization\ByDao\Authorization;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO;
use Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO;

class AuthorizationTest
{
    public function authorize(): array
    {
        $authorization = new Authorization("forbidden", "login");

        $allowed = $authorization->authorize(
            new MockPageAuthorizationDAO("index"),
            new MockUserAuthorizationDAO(1),
            "GET"
        );
        $denied = $authorization->authorize(
            new MockPageAuthorizationDAO("index"),
            new MockUserAuthorizationDAO(null),
            "GET"
        );
        $missing = $authorization->authorize(
            new MockPageAuthorizationDAO("missing"),
            new MockUserAuthorizationDAO(1),
            "GET"
        );

        return [
            (new Booleans($allowed->getStatus() === ResultStatus::OK))->assertTrue(),
            (new Booleans($denied->getStatus() === ResultStatus::UNAUTHORIZED))->assertTrue(),
            (new Booleans($missing->getStatus() === ResultStatus::NOT_FOUND))->assertTrue()
        ];
    }
}

