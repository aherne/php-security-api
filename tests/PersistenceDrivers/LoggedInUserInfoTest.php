<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;

final class LoggedInUserInfoTest
{
    private function userInfo(): LoggedInUserInfo
    {
        return new LoggedInUserInfo(7, AuthenticationStage::PENDING_MFA, true, 1234567890);
    }

    public function getUserID()
    {
        return (new Integers($this->userInfo()->getUserID()))->assertEquals(7);
    }

    public function getAuthenticatedStage()
    {
        $actual = $this->userInfo()->getAuthenticatedStage();

        return (new Arrays([$actual]))->assertIdentical([AuthenticationStage::PENDING_MFA]);
    }

    public function getStageValidUntil()
    {
        return (new Integers($this->userInfo()->getStageValidUntil()))->assertEquals(1234567890);
    }

    public function rememberRequested()
    {
        return (new Booleans($this->userInfo()->rememberRequested()))->assertTrue();
    }
}
