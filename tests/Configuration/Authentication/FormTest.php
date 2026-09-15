<?php

namespace Test\Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Authentication\Form;
use Test\Lucinda\WebSecurity\mocks\Authentication\FormLoginDAO;
use Test\Lucinda\WebSecurity\mocks\Authentication\FormLoginThrottler;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class FormTest
{
    private function configuration(): Form
    {
        return new Form(Fixture::node("form"));
    }

    public function getDAO()
    {
        $actual = $this->configuration()->getDAO();

        return (new Strings($actual))->assertEquals(FormLoginDAO::class);
    }

    public function getThrottler()
    {
        $actual = $this->configuration()->getThrottler();

        return (new Strings($actual))->assertEquals(FormLoginThrottler::class);
    }

    public function getPageSource()
    {
        $actual = $this->configuration()->getPageSource();

        return (new Strings($actual))->assertEquals("sign-in");
    }

    public function getTargetThrottled()
    {
        $actual = $this->configuration()->getTargetThrottled();

        return (new Strings($actual))->assertEquals("slow-down");
    }

    public function getParameterUsername()
    {
        $actual = $this->configuration()->getParameterUsername();

        return (new Strings($actual))->assertEquals("email");
    }

    public function getParameterPassword()
    {
        $actual = $this->configuration()->getParameterPassword();

        return (new Strings($actual))->assertEquals("passphrase");
    }

    public function getParameterRememberMe()
    {
        $actual = $this->configuration()->getParameterRememberMe();

        return (new Strings($actual))->assertEquals("remember");
    }

    public function getParameterCsrf()
    {
        $actual = $this->configuration()->getParameterCsrf();

        return (new Strings($actual))->assertEquals("token");
    }

    public function getTargetSuccess()
    {
        $actual = $this->configuration()->getTargetSuccess();

        return (new Strings($actual))->assertEquals("dashboard");
    }

    public function getTargetFailure()
    {
        $actual = $this->configuration()->getTargetFailure();

        return (new Strings($actual))->assertEquals("denied");
    }
}
