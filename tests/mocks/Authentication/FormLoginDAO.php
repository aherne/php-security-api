<?php

namespace Test\Lucinda\WebSecurity\mocks\Authentication;

use Lucinda\WebSecurity\DAO\FormLogin;

final class FormLoginDAO implements FormLogin
{
    public static int|string|null $result = 7;

    public function login(string $username, string $password): int|string|null
    {
        return self::$result;
    }
}
