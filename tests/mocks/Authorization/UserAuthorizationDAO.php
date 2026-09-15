<?php

namespace Test\Lucinda\WebSecurity\mocks\Authorization;

use Lucinda\WebSecurity\DAO\UserAuthorization;

final class UserAuthorizationDAO implements UserAuthorization
{
    public static bool $allowed = true;

    public function isAllowed(int|string $userID, int $pageID, string $httpRequestMethod): bool
    {
        return self::$allowed;
    }
}
