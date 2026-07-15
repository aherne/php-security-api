<?php
namespace Test\Lucinda\WebSecurity\Security\Authorization;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Configuration\Authorization\ByDAO as ByDAOConfiguration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authorization\ByDao;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;

class ByDaoTest
{
    public function getResult()
    {
        $configuration = new ByDAOConfiguration(simplexml_load_string(
            '<by_dao page_dao="Test\\Lucinda\\WebSecurity\\mocks\\Authorization\\MockPageAuthorizationDAO"
                user_dao="Test\\Lucinda\\WebSecurity\\mocks\\Authorization\\MockUserAuthorizationDAO"
                logged_in_callback="forbidden" logged_out_callback="login"/>'
        ));
        $request = new Request();
        $request->setUri("index");
        $request->setMethod("GET");
        $authorizer = new ByDao($configuration, $request, 1);

        return (new Booleans($authorizer->getResult()->getStatus() === ResultStatus::OK))->assertTrue();
    }
}
