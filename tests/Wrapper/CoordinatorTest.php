<?php

namespace Test\Lucinda\WebSecurity\Wrapper;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\Wrapper\Coordinator;
use Test\Lucinda\WebSecurity\mocks\PersistenceDriver;

final class CoordinatorTest
{
    public function save()
    {
        $first = new PersistenceDriver();
        $second = new PersistenceDriver();
        $userInfo = new LoggedInUserInfo(7, AuthenticationStage::AUTHENTICATED);
        (new Coordinator([$first, $second]))->save($userInfo);

        return (new Arrays([$first->stored, $second->stored]))->assertIdentical([$userInfo, $userInfo]);
    }

    public function clear()
    {
        $first = new PersistenceDriver();
        $second = new PersistenceDriver();
        (new Coordinator([$first, $second]))->clear();

        return (new Integers($first->clears + $second->clears))->assertEquals(2);
    }
}
