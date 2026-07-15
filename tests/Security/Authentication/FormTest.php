<?php
namespace Test\Lucinda\WebSecurity\Security\Authentication;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Configuration\Authentication\Form as FormConfiguration;
use Lucinda\WebSecurity\Configuration\Csrf;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authentication\Form;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockLoginThrottler;

class FormTest
{
    public function getOutcome()
    {
        $configuration = new FormConfiguration(simplexml_load_string(
            '<form dao="Test\\Lucinda\\WebSecurity\\mocks\\Authentication\\MockUsersAuthentication">
                <login page="login" target_success="home" target_failure="retry"/>
                <logout page="logout" target_success="bye" target_failure="error"/>
            </form>'
        ));
        $csrf = new CsrfToken(
            new Csrf(simplexml_load_string('<xml><csrf secret="abcdefghijklmnopqrstuvwxyz123456"/></xml>')),
            "127.0.0.1"
        );
        $request = new Request();
        $request->setUri("login");
        $request->setMethod("POST");
        $request->setParameters([]);
        $request->setContextPath("");
        $request->setIpAddress("127.0.0.1");

        $authentication = new Form(
            $configuration,
            $request,
            new MockLoginThrottler(),
            $csrf,
            null
        );

        return (new Booleans($authentication->getOutcome()->getStatus() === ResultStatus::LOGIN_FAILED))->assertTrue();
    }
}
