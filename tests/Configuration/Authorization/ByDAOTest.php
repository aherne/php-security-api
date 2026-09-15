<?php

namespace Test\Lucinda\WebSecurity\Configuration\Authorization;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Authorization\ByDAO;
use Test\Lucinda\WebSecurity\mocks\Authorization\PageAuthorizationDAO;
use Test\Lucinda\WebSecurity\mocks\Authorization\UserAuthorizationDAO;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class ByDAOTest
{
    private function configuration(): ByDAO
    {
        return new ByDAO(Fixture::node("authorization-dao"));
    }

    public function getPageDAO()
    {
        $actual = $this->configuration()->getPageDAO();

        return (new Strings($actual))->assertEquals(PageAuthorizationDAO::class);
    }

    public function getUserDAO()
    {
        $actual = $this->configuration()->getUserDAO();

        return (new Strings($actual))->assertEquals(UserAuthorizationDAO::class);
    }

    public function getCallbackLoggedIn()
    {
        $actual = $this->configuration()->getCallbackLoggedIn();

        return (new Strings($actual))->assertEquals("forbidden");
    }

    public function getCallbackLoggedOut()
    {
        $actual = $this->configuration()->getCallbackLoggedOut();

        return (new Strings($actual))->assertEquals("login");
    }
}
