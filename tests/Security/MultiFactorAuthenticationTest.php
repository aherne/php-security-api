<?php

namespace Test\Lucinda\WebSecurity\Security;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus;
use Test\Lucinda\WebSecurity\Support\Fixture;
use Test\Lucinda\WebSecurity\mocks\Authentication\MultiFactorAuthenticationDAO;

final class MultiFactorAuthenticationTest
{
    public function getOutcome()
    {
        $configuration = Fixture::configuration(true)->getMultiFactorAuthentication();
        $expiredPending = new LoggedInUserInfo(7, AuthenticationStage::PENDING_MFA, false, time() - 1);
        $expiredOutcome = (new MultiFactorAuthentication($configuration, Fixture::request("home"), $expiredPending))->getOutcome();

        $freshAuthenticated = new LoggedInUserInfo(7, AuthenticationStage::AUTHENTICATED, false, time() + 300);
        $freshOutcome = (new MultiFactorAuthentication($configuration, Fixture::request("home"), $freshAuthenticated))->getOutcome();

        MultiFactorAuthenticationDAO::reset();
        $staleAuthenticated = new LoggedInUserInfo(7, AuthenticationStage::AUTHENTICATED, false, time() - 1);
        $staleOutcome = (new MultiFactorAuthentication($configuration, Fixture::request("home"), $staleAuthenticated))->getOutcome();

        return [
            (new Arrays([$expiredOutcome->getStatus(), $expiredOutcome->getUserID()]))
                ->assertIdentical([ResultStatus::EXPIRED, 7]),
            (new Arrays([$freshOutcome]))->assertIdentical([null]),
            (new Arrays([$staleOutcome->getStatus(), $staleOutcome->getUserID()]))
                ->assertIdentical([ResultStatus::REQUIRED, 7])
        ];
    }
}
