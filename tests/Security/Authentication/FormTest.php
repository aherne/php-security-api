<?php

namespace Test\Lucinda\WebSecurity\Security\Authentication;

use Lucinda\UnitTest\Validator\Objects;
use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Packets\GuestUser;
use Lucinda\WebSecurity\Packets\Throttling;
use Lucinda\WebSecurity\Security\Authentication\Form;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Lucinda\WebSecurity\Security\FailureReason;
use Test\Lucinda\WebSecurity\mocks\Authentication\FormLoginDAO;
use Test\Lucinda\WebSecurity\mocks\Authentication\FormLoginThrottler;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class FormTest
{
    public function getOutcome()
    {
        FormLoginThrottler::reset();
        FormLoginDAO::$result = 7;
        $configuration = Fixture::configuration();
        $formConfiguration = $configuration->getAuthentication()->getLoginMethods()[0];

        $getRequest = Fixture::request("login");
        $csrf = new CsrfToken($configuration->getCsrf(), $getRequest->getIpAddress());
        $guestOutcome = (new Form($formConfiguration, $getRequest, $csrf, null))->getOutcome();

        $postRequest = Fixture::request("login", "POST");
        $postRequest->setParameters([
            "username" => "person@example.com",
            "password" => "correct-password",
            "csrf" => $csrf->generate("guest")
        ]);
        $successOutcome = (new Form($formConfiguration, $postRequest, $csrf, null))->getOutcome();

        $invalidRequest = Fixture::request("login", "POST", []);
        $invalidOutcome = (new Form($formConfiguration, $invalidRequest, $csrf, null))->getOutcome();

        FormLoginThrottler::$throttled = true;
        $throttledOutcome = (new Form($formConfiguration, $postRequest, $csrf, null))->getOutcome();
        FormLoginThrottler::reset();

        return [
            (new Objects($guestOutcome))->assertInstanceOf(GuestUser::class),
            (new Arrays([$successOutcome->getStatus(), $successOutcome->getUserID()]))
                ->assertIdentical([ResultStatus::IDENTITY_VERIFIED, 7]),
            (new Arrays([$invalidOutcome->getStatus(), $invalidOutcome->getFailureReason()]))
                ->assertIdentical([ResultStatus::LOGIN_FAILED, FailureReason::FORM_PARAMETERS_INVALID]),
            (new Objects($throttledOutcome))->assertInstanceOf(Throttling::class)
        ];
    }
}
