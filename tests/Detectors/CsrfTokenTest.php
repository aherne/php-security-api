<?php
namespace Test\Lucinda\WebSecurity\Detectors;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Csrf;
use Lucinda\WebSecurity\Detectors\CsrfToken;

class CsrfTokenTest
{
    private function detector(): CsrfToken
    {
        $configuration = new Csrf(
            simplexml_load_string('<xml><csrf secret="abcdefghijklmnopqrstuvwxyz123456"/></xml>')
        );
        return new CsrfToken($configuration, "127.0.0.1");
    }

    public function generate()
    {
        return (new Strings($this->detector()->generate(12)))->assertNotEmpty();
    }

    public function isValid(): array
    {
        $detector = $this->detector();
        $token = $detector->generate("user");

        return [
            (new Booleans($detector->isValid($token, "user")))->assertTrue(),
            (new Booleans($detector->isValid($token, "other")))->assertFalse(),
            (new Booleans($detector->isValid("invalid", "user")))->assertFalse()
        ];
    }
}

