<?php

namespace Test\Lucinda\WebSecurity\Security;

use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Packets\GuestUser;
use Lucinda\WebSecurity\Security\Authentication;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class AuthenticationTest
{
    public function getOutcome()
    {
        $configuration = Fixture::configuration();
        $request = Fixture::request("login");
        $csrf = new CsrfToken($configuration->getCsrf(), $request->getIpAddress());
        $outcome = (new Authentication($configuration->getAuthentication(), $request, null, $csrf))->getOutcome();

        return (new Objects($outcome))->assertInstanceOf(GuestUser::class);
    }
}
