<?php

namespace Test\Lucinda\WebSecurity\mocks\Authentication;

use Lucinda\WebSecurity\DAO\Logout;

final class LogoutDAO implements Logout
{
    public static bool $result = true;

    public function logout(int|string $userID): bool
    {
        return self::$result;
    }
}
