<?php

namespace Test\Lucinda\WebSecurity\mocks\OAuth2;

use Lucinda\WebSecurity\DAO\OAuth2\Login;
use Lucinda\WebSecurity\DAO\OAuth2\UserInformation;

final class LoginDAO implements Login
{
    public static int|string|null $result = 7;

    public function resolve(UserInformation $userInformation, string $vendorName): int|string|null
    {
        return self::$result;
    }
}
