<?php
namespace Test\Lucinda\WebSecurity\Configuration\Authorization;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Authorization\ByDAO;
use Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO;
use Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO;

class ByDAOTest
{
    private function subject(): ByDAO
    {
        return new ByDAO(simplexml_load_string('<by_dao page_dao="Test\\Lucinda\\WebSecurity\\mocks\\Authorization\\MockPageAuthorizationDAO" user_dao="Test\\Lucinda\\WebSecurity\\mocks\\Authorization\\MockUserAuthorizationDAO" logged_in_callback="forbidden" logged_out_callback="login"/>'));
    }

    public function getPageDAO()
    {
        return (new Strings($this->subject()->getPageDAO()))->assertEquals(MockPageAuthorizationDAO::class);
    }

    public function getUserDAO()
    {
        return (new Strings($this->subject()->getUserDAO()))->assertEquals(MockUserAuthorizationDAO::class);
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
