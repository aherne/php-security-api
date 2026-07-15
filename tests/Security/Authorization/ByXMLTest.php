<?php
namespace Test\Lucinda\WebSecurity\Security\Authorization;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Configuration\Authorization\ByXML;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authorization\ByXML as ByXMLAuthorizer;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;

class ByXMLTest
{
    public function getResult()
    {
        $configuration = new ByXML(simplexml_load_string(
            '<by_route roles_dao="Test\\Lucinda\\WebSecurity\\mocks\\Authorization\\MockUserRolesDAO"
                logged_in_callback="forbidden" logged_out_callback="login"/>'
        ));
        $request = new Request();
        $request->setUri("home");
        $routes = simplexml_load_string('<xml><routes><route id="home" roles="USER"/></routes></xml>');
        $authorizer = new ByXMLAuthorizer($configuration, $request, 1, $routes);

        return (new Booleans($authorizer->getResult()->getStatus() === ResultStatus::OK))->assertTrue();
    }
}

