<?php

namespace Test\Lucinda\WebSecurity\mocks\Authentication;

use Lucinda\WebSecurity\DAO\FormAuthentication;
use Lucinda\WebSecurity\DAO\UserRoles;

class MockUsersAuthentication implements FormAuthentication, UserRoles
{
    public function login(string $username, string $password): int|string|null
    {
        return ($username=="test" && $password=="me" ? 1 : null);
    }

    public function logout(int|string $userID): bool
    {
        return true;
    }

    public function getRoles(int|string|null $userID): array
    {
        if ($userID) {
            return ["USER"];
        } else {
            return ["GUEST"];
        }
    }
};
