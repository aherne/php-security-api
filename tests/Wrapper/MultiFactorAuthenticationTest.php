<?php

namespace Test\Lucinda\WebSecurity\Wrapper;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\Wrapper\MultiFactorAuthentication;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authentication\MultiFactorAuthenticationDAO;
use Test\Lucinda\WebSecurity\mocks\PersistenceDriver;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class MultiFactorAuthenticationTest
{
    private function execute(): MultiFactorAuthentication
    {
        MultiFactorAuthenticationDAO::$required = false;
        $pending = new LoggedInUserInfo(7, AuthenticationStage::PENDING_MFA, false, time() + 120);
        $wrapper = new MultiFactorAuthentication(
            Fixture::configuration(true),
            Fixture::request("home"),
            [new PersistenceDriver()],
            $pending
        );
        $wrapper->run();
        MultiFactorAuthenticationDAO::$required = true;

        return $wrapper;
    }

    public function run()
    {
        $promotedUserInfo = $this->execute()->getLoggedInUserInfo();

        MultiFactorAuthenticationDAO::$required = true;
        $driver = new PersistenceDriver();
        $expired = new LoggedInUserInfo(7, AuthenticationStage::PENDING_MFA, false, time() - 1);
        $wrapper = new MultiFactorAuthentication(
            Fixture::configuration(true),
            Fixture::request("home"),
            [$driver],
            $expired
        );
        $expiredOutcome = $wrapper->run();

        return [
            (new Arrays([$promotedUserInfo->getAuthenticatedStage(), $promotedUserInfo->getStageValidUntil()]))
                ->assertIdentical([AuthenticationStage::AUTHENTICATED, null]),
            (new Arrays([$expiredOutcome->getStatus(), $wrapper->getLoggedInUserInfo(), $driver->clears]))
                ->assertIdentical([ResultStatus::EXPIRED, null, 1])
        ];
    }

    public function getLoggedInUserInfo()
    {
        $userInfo = $this->execute()->getLoggedInUserInfo();

        return (new Arrays([$userInfo->getUserID(), $userInfo->getAuthenticatedStage()]))
            ->assertIdentical([7, AuthenticationStage::AUTHENTICATED]);
    }
}
