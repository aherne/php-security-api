<?php

namespace Test\Lucinda\WebSecurity\mocks\Authorization;

use Lucinda\WebSecurity\DAO\PageAuthorization;
use Lucinda\WebSecurity\DAO\UserAuthorization;

class MockUserAuthorizationDAO extends UserAuthorization
{
    public function isAllowed(PageAuthorization $page, string $httpRequestMethod): bool
    {
        if ($page->isPublic()) {
            return true;
        }
        // user id 1 only has access to page id 2
        return $this->userID==1 && $page->getID()==2;
    }
}
