<?php

namespace Test\Lucinda\WebSecurity\Configuration\MultiFactorAuthentication;

use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication\Totp;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class TotpTest
{
    private function configuration(): Totp
    {
        return new Totp(Fixture::node("totp"));
    }

    public function getIssuer()
    {
        $actual = $this->configuration()->getIssuer();

        return (new Strings($actual))->assertEquals("Example");
    }

    public function getCodeParameter()
    {
        $actual = $this->configuration()->getCodeParameter();

        return (new Strings($actual))->assertEquals("verification_code");
    }

    public function getPeriod()
    {
        $actual = $this->configuration()->getPeriod();

        return (new Integers($actual))->assertEquals(60);
    }

    public function getDigits()
    {
        $actual = $this->configuration()->getDigits();

        return (new Integers($actual))->assertEquals(8);
    }

    public function getWindow()
    {
        $actual = $this->configuration()->getWindow();

        return (new Integers($actual))->assertEquals(2);
    }
}
