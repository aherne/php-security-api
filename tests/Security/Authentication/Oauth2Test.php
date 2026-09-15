<?php

namespace Test\Lucinda\WebSecurity\Security\Authentication;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2 as Configuration;
use Lucinda\WebSecurity\Security\Authentication\Oauth2;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Lucinda\WebSecurity\Security\FailureReason;
use Test\Lucinda\WebSecurity\mocks\OAuth2\LoginDAO;
use Test\Lucinda\WebSecurity\mocks\OAuth2\Service;
use Test\Lucinda\WebSecurity\mocks\OAuth2\State;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class Oauth2Test
{
    public function getOutcome()
    {
        $configuration = new Configuration(Fixture::node("oauth-existing"));
        $service = new Service();
        $state = new State();
        $request = Fixture::request("oauth/callback");
        $redirectOutcome = (new Oauth2($configuration, $request, null, ["example" => $service], $state))->getOutcome();

        LoginDAO::$result = 7;
        $callbackRequest = Fixture::request("oauth/callback", "GET", ["state" => "accepted", "code" => "code"]);
        $successOutcome = (new Oauth2($configuration, $callbackRequest, null, ["example" => $service], $state))->getOutcome();

        $state->accepted = false;
        $rejectedOutcome = (new Oauth2($configuration, $callbackRequest, null, ["example" => $service], $state))->getOutcome();

        return [
            (new Arrays([$redirectOutcome->getStatus()]))->assertIdentical([ResultStatus::DEFERRED]),
            (new Strings($redirectOutcome->getCallback()))->assertContains("https://provider.example/authorize?state="),
            (new Arrays([$successOutcome->getStatus(), $successOutcome->getUserID()]))
                ->assertIdentical([ResultStatus::IDENTITY_VERIFIED, 7]),
            (new Arrays([$rejectedOutcome->getStatus(), $rejectedOutcome->getFailureReason()]))
                ->assertIdentical([ResultStatus::LOGIN_FAILED, FailureReason::OAUTH_INVALID_STATE])
        ];
    }
}
