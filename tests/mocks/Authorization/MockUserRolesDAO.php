<?php

namespace Test\Lucinda\WebSecurity\mocks\Authorization;

use Lucinda\WebSecurity\DAO\UserRoles;

class MockUserRolesDAO implements UserRoles
{
    public function getRoles(int|string|null $userID): array
    {
        if ($userID) {
            return ["USER"];
        } else {
            return ["GUEST"];
        }
    }
}
