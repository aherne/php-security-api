<?php

namespace Test\Lucinda\WebSecurity\Wrapper;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Packets\LoggedInUser;
use Lucinda\WebSecurity\Packets\Security;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Lucinda\WebSecurity\Wrapper\OutcomeBuilder;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class OutcomeBuilderTest
{
    public function getOutcome()
    {
        $configuration = Fixture::configuration();
        $csrf = new CsrfToken($configuration->getCsrf(), "127.0.0.1");
        $packet = new Security(ResultStatus::LOGIN_OK, "/home");
        $userInfo = new LoggedInUserInfo(7, AuthenticationStage::AUTHENTICATED);
        $outcome = (new OutcomeBuilder($packet, $userInfo, $csrf))->getOutcome();

        $failurePacket = new Security(ResultStatus::LOGIN_FAILED, "/login-failed");
        $preservedFailure = (new OutcomeBuilder($failurePacket, $userInfo, $csrf))->getOutcome();

        $pending = new LoggedInUserInfo(7, AuthenticationStage::PENDING_MFA, false, time() + 120);
        $pendingOutcome = (new OutcomeBuilder(null, $pending, $csrf))->getOutcome();

        return [
            (new Objects($outcome))->assertInstanceOf(LoggedInUser::class),
            (new Arrays([$outcome->getUserID(), $outcome->getCallback()]))->assertIdentical([7, "/home"]),
            (new Arrays([$preservedFailure]))->assertIdentical([$failurePacket]),
            (new Arrays([$pendingOutcome]))->assertIdentical([null])
        ];
    }
}
