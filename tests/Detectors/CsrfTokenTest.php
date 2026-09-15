<?php

namespace Test\Lucinda\WebSecurity\Detectors;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class CsrfTokenTest
{
    public function generate()
    {
        $detector = new CsrfToken(Fixture::configuration()->getCsrf(), "127.0.0.1");
        $token = $detector->generate(7);

        return (new Strings($token))->assertNotEmpty();
    }

    public function isValid()
    {
        $detector = new CsrfToken(Fixture::configuration()->getCsrf(), "127.0.0.1");
        $token = $detector->generate(7);
        $isValid = $detector->isValid($token, 7);

        return (new Booleans($isValid))->assertTrue();
    }
}
