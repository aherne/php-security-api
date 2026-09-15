<?php

namespace Test\Lucinda\WebSecurity\mocks\Authorization;

use Lucinda\WebSecurity\DAO\PageAuthorization;

final class PageAuthorizationDAO implements PageAuthorization
{
    public static ?int $pageID = 10;
    public static bool $public = false;

    public function isPublic(int $pageID): bool
    {
        return self::$public;
    }

    public function getID(string $pageURL): ?int
    {
        return self::$pageID;
    }
}
