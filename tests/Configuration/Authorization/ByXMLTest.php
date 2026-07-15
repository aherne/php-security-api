<?php
namespace Test\Lucinda\WebSecurity\Configuration\Authorization;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Authorization\ByXML;
use Test\Lucinda\WebSecurity\mocks\Authorization\MockUserRolesDAO;

class ByXMLTest
{
    private function subject(): ByXML
    {
        return new ByXML(simplexml_load_string('<by_route roles_dao="Test\\Lucinda\\WebSecurity\\mocks\\Authorization\\MockUserRolesDAO" logged_in_callback="forbidden" logged_out_callback="login"/>'));
    }

    public function getRolesDAO()
    {
        return (new Strings($this->subject()->getRolesDAO()))->assertEquals(MockUserRolesDAO::class);
    }

    public function getCallbackLoggedIn()
    {
        return (new Strings($this->subject()->getCallbackLoggedIn()))->assertEquals("forbidden");
    }

    public function getCallbackLoggedOut()
    {
        return (new Strings($this->subject()->getCallbackLoggedOut()))->assertEquals("login");
    }
}
