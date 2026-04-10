<?php

namespace Test\Lucinda\WebSecurity\Authentication\Form;

use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Authentication\Form\LoginConfiguration;

class LoginConfigurationTest
{
    private LoginConfiguration $configuration1;
    private LoginConfiguration $configuration2;

    public function __construct()
    {
        $xml1 = simplexml_load_string(
            '
<security>
    <authentication>
        <form>
            <login parameter_username="user" parameter_password="pass"   parameter_rememberMe="rm" page="test" target="me"/>  
        </form>
    </authentication>
</security>'
        );
        $this->configuration1 = new LoginConfiguration($xml1->authentication->form);
        $xml2 = simplexml_load_string(
            '
<security>
    <authentication>
        <form>
        </form>
    </authentication>
</security>'
        );
        $this->configuration2 = new LoginConfiguration($xml2->authentication->form);
    }


    public function getUsername()
    {
        $output = [];
        $output[] = (new Strings($this->configuration1->getUsername()))->assertEquals("user", "manual");
        $output[] = (new Strings($this->configuration2->getUsername()))->assertEquals("username", "implied");
        return $output;
    }


    public function getPassword()
    {
        $output = [];
        $output[] = (new Strings($this->configuration1->getPassword()))->assertEquals("pass", "manual");
        $output[] = (new Strings($this->configuration2->getPassword()))->assertEquals("password", "implied");
        return $output;
    }


    public function getRememberMe()
    {
        $output = [];
        $output[] = (new Strings($this->configuration1->getRememberMe()))->assertEquals("rm", "manual");
        $output[] = (new Strings($this->configuration2->getRememberMe()))->assertEquals("remember_me", "implied");
        return $output;
    }


    public function getSourcePage()
    {
        $output = [];
        $output[] = (new Strings($this->configuration1->getSourcePage()))->assertEquals("test", "manual");
        $output[] = (new Strings($this->configuration2->getSourcePage()))->assertEquals("", "implied");
        return $output;
    }


    public function getDestinationPage()
    {
        $output = [];
        $output[] = (new Strings($this->configuration1->getDestinationPage()))->assertEquals("me", "manual");
        $output[] = (new Strings($this->configuration2->getDestinationPage()))->assertEquals("", "implied");
        return $output;
    }
}
