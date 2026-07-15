<?php
namespace Test\Lucinda\WebSecurity\Security\Authentication;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2 as Oauth2Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authentication\Oauth2;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockOauth2Driver;

class Oauth2Test
{
    public function getOutcome(): array
    {
        $configuration = new Oauth2Configuration(simplexml_load_string(
            '<oauth2 dao="Test\\Lucinda\\WebSecurity\\mocks\\Authentication\\MockVendorAuthenticationDAO"
                logout="logout" target_login_success="home" target_login_failure="retry"
                target_logout_success="bye" target_logout_failure="error">
                <driver name="Facebook" login="login/facebook"/>
            </oauth2>'
        ));
        $request = new Request();
        $request->setUri("login/facebook");
        $request->setParameters([]);
        $request->setContextPath("");

        $authentication = new Oauth2(
            $configuration,
            $request,
            null,
            ["Facebook" => new MockOauth2Driver("Facebook")]
        );
        $outcome = $authentication->getOutcome();

        return [
            (new Booleans($outcome->getStatus() === ResultStatus::DEFERRED))->assertTrue(),
            (new Strings($outcome->getCallback() ?? ""))->assertEquals("qwerty")
        ];
    }
}

