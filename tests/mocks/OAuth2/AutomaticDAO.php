<?php

namespace Test\Lucinda\WebSecurity\mocks\OAuth2;

use Lucinda\WebSecurity\DAO\OAuth2\AutomaticProvisioning;
use Lucinda\WebSecurity\DAO\OAuth2\UserInformation;

final class AutomaticDAO implements AutomaticProvisioning
{
    public static int|string|null $resolved = null;
    public static int|string|null $created = 8;

    public function resolve(UserInformation $userInformation, string $vendorName): int|string|null
    {
        return self::$resolved;
    }

    public function create(UserInformation $userInformation, string $vendorName): int|string|null
    {
        return self::$created;
    }
}
