<?php

namespace Test\Lucinda\WebSecurity\mocks\Authorization;

use Lucinda\WebSecurity\DAO\UserRoles;

final class UserRolesDAO implements UserRoles
{
    public static array $roles = ["USER"];

    public function getRoles(int|string|null $userID): array
    {
        return self::$roles;
    }
}
