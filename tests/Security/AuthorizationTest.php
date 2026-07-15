<?php
namespace Test\Lucinda\WebSecurity\Security;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Configuration\Authorization as AuthorizationConfiguration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authorization;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;

class AuthorizationTest
{
    public function getOutcome()
    {
        $configuration = new AuthorizationConfiguration(simplexml_load_string('
            <xml><authorization>
                <by_dao page_dao="Test\\Lucinda\\WebSecurity\\mocks\\Authorization\\MockPageAuthorizationDAO"
                    user_dao="Test\\Lucinda\\WebSecurity\\mocks\\Authorization\\MockUserAuthorizationDAO"
                    logged_in_callback="forbidden" logged_out_callback="login"/>
            </authorization></xml>
        '));
        $request = new Request();
        $request->setUri("index");
        $request->setMethod("GET");
        $authorization = new Authorization($configuration, $request, 1);

        return (new Booleans($authorization->getOutcome()->getStatus() === ResultStatus::OK))->assertTrue();
    }
}

