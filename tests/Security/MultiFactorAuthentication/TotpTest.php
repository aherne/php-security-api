<?php

namespace Test\Lucinda\WebSecurity\Security\MultiFactorAuthentication;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Packets\Throttling;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp;
use Test\Lucinda\WebSecurity\mocks\Authentication\MultiFactorAuthenticationDAO;
use Test\Lucinda\WebSecurity\mocks\Authentication\MultiFactorAuthenticationThrottler;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class TotpTest
{
    public function getOutcome()
    {
        MultiFactorAuthenticationDAO::reset();
        MultiFactorAuthenticationThrottler::reset();
        $configuration = Fixture::configuration(true)->getMultiFactorAuthentication();

        MultiFactorAuthenticationDAO::$required = false;
        $notRequired = (new Totp($configuration, Fixture::request("home"), 7))->getOutcome();

        MultiFactorAuthenticationDAO::$required = true;
        $challengeRequired = (new Totp($configuration, Fixture::request("home"), 7))->getOutcome();

        MultiFactorAuthenticationThrottler::$throttled = true;
        $throttled = (new Totp($configuration, Fixture::request("home"), 7))->getOutcome();

        MultiFactorAuthenticationThrottler::reset();
        MultiFactorAuthenticationDAO::$secret = null;
        $setupRequired = (new Totp($configuration, Fixture::request("home"), 7))->getOutcome();
        MultiFactorAuthenticationDAO::reset();

        return [
            (new Arrays([$notRequired->getStatus(), $notRequired->getCallback()]))
                ->assertIdentical([ResultStatus::NOT_REQUIRED, "/app//mfa/success"]),
            (new Arrays([$challengeRequired->getStatus(), $challengeRequired->getUserID()]))
                ->assertIdentical([ResultStatus::REQUIRED, 7]),
            (new Objects($throttled))->assertInstanceOf(Throttling::class),
            (new Arrays([$setupRequired->getStatus()]))
                ->assertIdentical([ResultStatus::SETUP_REQUIRED])
        ];
    }
}
