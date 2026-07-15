<?php
namespace Test\Lucinda\WebSecurity\Security;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Configuration\Authentication as AuthenticationConfiguration;
use Lucinda\WebSecurity\Configuration\Csrf;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authentication;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockLoginThrottler;

class AuthenticationTest
{
    public function getOutcome()
    {
        $configuration = new AuthenticationConfiguration(simplexml_load_string(
            '<xml><authentication>
                <form dao="Test\\Lucinda\\WebSecurity\\mocks\\Authentication\\MockUsersAuthentication">
                    <login page="login" target_success="home" target_failure="retry"/>
                    <logout page="logout" target_success="bye" target_failure="error"/>
                </form>
            </authentication></xml>'
        ));
        $request = new Request();
        $request->setUri("login");
        $request->setMethod("POST");
        $request->setParameters([]);
        $request->setContextPath("");
        $request->setIpAddress("127.0.0.1");
        $csrf = new CsrfToken(
            new Csrf(simplexml_load_string('<xml><csrf secret="abcdefghijklmnopqrstuvwxyz123456"/></xml>')),
            "127.0.0.1"
        );
        $authentication = new Authentication(
            $configuration,
            $request,
            null,
            new MockLoginThrottler(),
            $csrf
        );

        return (new Booleans($authentication->getOutcome()->getStatus() === ResultStatus::LOGIN_FAILED))->assertTrue();
    }
}

