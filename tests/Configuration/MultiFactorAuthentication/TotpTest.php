<?php
namespace Test\Lucinda\WebSecurity\Configuration\MultiFactorAuthentication;

use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication\Totp;

class TotpTest
{
    private function subject(): Totp
    {
        $xml = simplexml_load_string(
            '<totp issuer="App" code_param="otp" period="60" digits="8" window="2"/>'
        );

        return new Totp($xml);
    }

    public function getIssuer()
    {
        return (new Strings($this->subject()->getIssuer()))->assertEquals("App");
    }

    public function getCodeParameter()
    {
        return (new Strings($this->subject()->getCodeParameter()))->assertEquals("otp");
    }

    public function getPeriod()
    {
        return (new Integers($this->subject()->getPeriod()))->assertEquals(60);
    }

    public function getDigits()
    {
        return (new Integers($this->subject()->getDigits()))->assertEquals(8);
    }

    public function getWindow()
    {
        return (new Integers($this->subject()->getWindow()))->assertEquals(2);
    }
}
