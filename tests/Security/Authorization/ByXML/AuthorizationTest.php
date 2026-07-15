<?php
namespace Test\Lucinda\WebSecurity\Security\Authorization\ByXML;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Security\Authorization\ByXML\Authorization;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authorization\MockUserRolesDAO;

class AuthorizationTest
{
    public function authorize(): array
    {
        $authorization = new Authorization("forbidden", "login");
        $routes = simplexml_load_string('
            <xml><routes>
                <route id="home" roles="USER"/>
                <route id="admin" roles="ADMIN"/>
            </routes></xml>
        ');
        $roles = new MockUserRolesDAO();

        return [
            (new Booleans($authorization->authorize($routes, "home", 1, $roles)->getStatus() === ResultStatus::OK))->assertTrue(),
            (new Booleans($authorization->authorize($routes, "admin", 1, $roles)->getStatus() === ResultStatus::FORBIDDEN))->assertTrue(),
            (new Booleans($authorization->authorize($routes, "home", null, $roles)->getStatus() === ResultStatus::UNAUTHORIZED))->assertTrue(),
            (new Booleans($authorization->authorize($routes, "missing", null, $roles)->getStatus() === ResultStatus::NOT_FOUND))->assertTrue()
        ];
    }
}

