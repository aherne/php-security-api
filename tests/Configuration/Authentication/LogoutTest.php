<?php

namespace Test\Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Authentication\Logout;
use Test\Lucinda\WebSecurity\mocks\Authentication\LogoutDAO;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class LogoutTest
{
    private function configuration(): Logout
    {
        return new Logout(Fixture::node("logout"));
    }

    public function getDAO()
    {
        $actual = $this->configuration()->getDAO();

        return (new Strings($actual))->assertEquals(LogoutDAO::class);
    }

    public function getPageSource()
    {
        $actual = $this->configuration()->getPageSource();

        return (new Strings($actual))->assertEquals("sign-out");
    }

    public function getParameterCsrf()
    {
        $actual = $this->configuration()->getParameterCsrf();

        return (new Strings($actual))->assertEquals("token");
    }

    public function getTargetSuccess()
    {
        $actual = $this->configuration()->getTargetSuccess();

        return (new Strings($actual))->assertEquals("goodbye");
    }

    public function getTargetFailure()
    {
        $actual = $this->configuration()->getTargetFailure();

        return (new Strings($actual))->assertEquals("denied");
    }
}
