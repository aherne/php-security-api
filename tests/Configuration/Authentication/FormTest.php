<?php
namespace Test\Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\UnitTest\Validator\Objects;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Authentication\Form;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockUsersAuthentication;

class FormTest
{
    private function subject(): Form
    {
        return new Form(simplexml_load_string('<form dao="Test\\Lucinda\\WebSecurity\\mocks\\Authentication\\MockUsersAuthentication"><login page="login" target_success="home" target_failure="retry"/><logout page="logout" target_success="bye" target_failure="error"/></form>'));
    }

    public function getDAO()
    {
        return (new Strings($this->subject()->getDAO()))->assertEquals(MockUsersAuthentication::class);
    }

    public function getLoginPolicy()
    {
        return (new Objects($this->subject()->getLoginPolicy()))->assertInstanceOf(Form\Login::class);
    }

    public function getLogoutPolicy()
    {
        return (new Objects($this->subject()->getLogoutPolicy()))->assertInstanceOf(Form\Logout::class);
    }
    public function getThrottler()
    {
    }
        

    public function getPageSource()
    {
    }
        

    public function getTargetThrottled()
    {
    }
        

    public function getParameterUsername()
    {
    }
        

    public function getParameterPassword()
    {
    }
        

    public function getParameterRememberMe()
    {
    }
        

    public function getTargetSuccess()
    {
    }
        

    public function getTargetFailure()
    {
    }
        

    public function getParameterCsrf()
    {
    }
        

}
