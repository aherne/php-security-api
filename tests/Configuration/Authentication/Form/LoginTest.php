<?php
namespace Test\Lucinda\WebSecurity\Configuration\Authentication\Form;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class LoginTest
{
    private function subject(): \Lucinda\WebSecurity\Configuration\Authentication\Form\Login
    {
        return new \Lucinda\WebSecurity\Configuration\Authentication\Form\Login(simplexml_load_string('<login page="sign-in" target_success="home" target_failure="retry" parameter_username="email" parameter_password="pass" parameter_remember_me="stay" csrf="token"/>'));
    }

    public function getPageSource()
    {
        return (new Strings($this->subject()->getPageSource()))->assertEquals("sign-in");
    }

    public function getTargetSuccess()
    {
        return (new Strings($this->subject()->getTargetSuccess()))->assertEquals("home");
    }

    public function getTargetFailure()
    {
        return (new Strings($this->subject()->getTargetFailure()))->assertEquals("retry");
    }

    public function getParameterUsername()
    {
        return (new Strings($this->subject()->getParameterUsername()))->assertEquals("email");
    }

    public function getParameterPassword()
    {
        return (new Strings($this->subject()->getParameterPassword()))->assertEquals("pass");
    }

    public function getParameterRememberMe()
    {
        return (new Strings($this->subject()->getParameterRememberMe()))->assertEquals("stay");
    }

    public function getParameterCsrf()
    {
        return (new Strings($this->subject()->getParameterCsrf()))->assertEquals("token");
    }
    public function getTargetThrottled()
    {
    }
        

}
