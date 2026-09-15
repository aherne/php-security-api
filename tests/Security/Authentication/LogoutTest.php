<?php

namespace Test\Lucinda\WebSecurity\Security\Authentication;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Security\Authentication\Logout;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Lucinda\WebSecurity\Security\FailureReason;
use Test\Lucinda\WebSecurity\mocks\Authentication\LogoutDAO;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class LogoutTest
{
    public function getOutcome()
    {
        $configuration = Fixture::configuration();
        $logoutConfiguration = $configuration->getAuthentication()->getLogoutMethod();

        $guestRequest = Fixture::request("logout");
        $csrf = new CsrfToken($configuration->getCsrf(), $guestRequest->getIpAddress());
        $guestOutcome = (new Logout($logoutConfiguration, $guestRequest, $csrf, null))->getOutcome();

        LogoutDAO::$result = true;
        $postRequest = Fixture::request("logout", "POST", ["csrf" => $csrf->generate(7)]);
        $successOutcome = (new Logout($logoutConfiguration, $postRequest, $csrf, 7))->getOutcome();

        $invalidOutcome = (new Logout($logoutConfiguration, $guestRequest, $csrf, 7))->getOutcome();

        return [
            (new Arrays([$guestOutcome->getStatus(), $guestOutcome->getCallback()]))
                ->assertIdentical([ResultStatus::DEFERRED, "/app//goodbye"]),
            (new Arrays([$successOutcome->getStatus()]))
                ->assertIdentical([ResultStatus::LOGOUT_OK]),
            (new Arrays([$invalidOutcome->getStatus(), $invalidOutcome->getFailureReason()]))
                ->assertIdentical([ResultStatus::LOGOUT_FAILED, FailureReason::LOGOUT_PARAMETERS_INVALID])
        ];
    }
}
