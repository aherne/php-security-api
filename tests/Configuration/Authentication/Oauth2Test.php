<?php
namespace Test\Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockVendorAuthenticationDAO;

class Oauth2Test
{
    private function subject(): Oauth2
    {
        return new Oauth2(simplexml_load_string('<oauth2 dao="Test\\Lucinda\\WebSecurity\\mocks\\Authentication\\MockVendorAuthenticationDAO" logout="logout" target_login_success="home" target_login_failure="retry" target_logout_success="bye" target_logout_failure="error"><driver name="github" login="login/github"/></oauth2>'));
    }

    public function getDAO()
    {
        return (new Strings($this->subject()->getDAO()))->assertEquals(MockVendorAuthenticationDAO::class);
    }

    public function getDrivers()
    {
        return (new Arrays($this->subject()->getDrivers()))->assertSize(1);
    }

    public function getPageLogout()
    {
        return (new Strings($this->subject()->getPageLogout()))->assertEquals("logout");
    }

    public function getTargetLoginSuccess()
    {
        return (new Strings($this->subject()->getTargetLoginSuccess()))->assertEquals("home");
    }

    public function getTargetLoginFailure()
    {
        return (new Strings($this->subject()->getTargetLoginFailure()))->assertEquals("retry");
    }

    public function getTargetLogoutSuccess()
    {
        return (new Strings($this->subject()->getTargetLogoutSuccess()))->assertEquals("bye");
    }

    public function getTargetLogoutFailure()
    {
        return (new Strings($this->subject()->getTargetLogoutFailure()))->assertEquals("error");
    }
}
