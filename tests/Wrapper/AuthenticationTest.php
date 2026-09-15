<?php

namespace Test\Lucinda\WebSecurity\Wrapper;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\Wrapper\Authentication;
use Test\Lucinda\WebSecurity\mocks\Authentication\FormLoginDAO;
use Test\Lucinda\WebSecurity\mocks\Authentication\FormLoginThrottler;
use Test\Lucinda\WebSecurity\mocks\PersistenceDriver;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class AuthenticationTest
{
    private function executeLogin(): Authentication
    {
        FormLoginDAO::$result = 7;
        FormLoginThrottler::reset();
        $configuration = Fixture::configuration();
        $request = Fixture::request("login", "POST");
        $csrf = new CsrfToken($configuration->getCsrf(), $request->getIpAddress());
        $request->setParameters([
            "username" => "person@example.com",
            "password" => "correct-password",
            "csrf" => $csrf->generate("guest")
        ]);
        $authentication = new Authentication($configuration, $request, $csrf, [new PersistenceDriver()]);
        $authentication->run();

        return $authentication;
    }

    public function run()
    {
        $userInfo = $this->executeLogin()->getLoggedInUserInfo();

        return (new Arrays([$userInfo->getUserID(), $userInfo->getAuthenticatedStage()]))
            ->assertIdentical([7, AuthenticationStage::AUTHENTICATED]);
    }

    public function getLoggedInUserInfo()
    {
        $userInfo = $this->executeLogin()->getLoggedInUserInfo();

        return (new Arrays([$userInfo->getUserID(), $userInfo->getAuthenticatedStage()]))
            ->assertIdentical([7, AuthenticationStage::AUTHENTICATED]);
    }
}
