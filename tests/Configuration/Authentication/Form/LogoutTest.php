<?php
namespace Test\Lucinda\WebSecurity\Configuration\Authentication\Form;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class LogoutTest
{
    private function subject(): \Lucinda\WebSecurity\Configuration\Authentication\Form\Logout
    {
        return new \Lucinda\WebSecurity\Configuration\Authentication\Form\Logout(simplexml_load_string('<logout page="sign-out" target_success="bye" target_failure="error"/>'));
    }

    public function getPageSource()
    {
        return (new Strings($this->subject()->getPageSource()))->assertEquals("sign-out");
    }

    public function getTargetSuccess()
    {
        return (new Strings($this->subject()->getTargetSuccess()))->assertEquals("bye");
    }

    public function getTargetFailure()
    {
        return (new Strings($this->subject()->getTargetFailure()))->assertEquals("error");
    }
    public function getParameterCsrf()
    {
    }
        

}
