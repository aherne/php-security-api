<?php

namespace Test\Lucinda\WebSecurity\Configuration\Authorization;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Authorization\ByXML;
use Test\Lucinda\WebSecurity\mocks\Authorization\UserRolesDAO;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class ByXMLTest
{
    private function configuration(): ByXML
    {
        return new ByXML(Fixture::node("authorization-xml"));
    }

    public function getRolesDAO()
    {
        $actual = $this->configuration()->getRolesDAO();

        return (new Strings($actual))->assertEquals(UserRolesDAO::class);
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
