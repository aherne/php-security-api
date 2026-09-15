<?php

namespace Test\Lucinda\WebSecurity\Detectors;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Detectors\UserInfo;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Test\Lucinda\WebSecurity\mocks\PersistenceDriver;

final class UserInfoTest
{
    public function getUserInfo()
    {
        $expected = new LoggedInUserInfo(7, AuthenticationStage::AUTHENTICATED);
        $driver = new PersistenceDriver();
        $driver->stored = $expected;
        $actual = (new UserInfo([$driver]))->getUserInfo();

        return (new Arrays([$actual]))->assertIdentical([$expected]);
    }
}
