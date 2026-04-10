<?php

namespace Test\Lucinda\WebSecurity\Authentication\Form;

use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Authentication\Form\LogoutConfiguration;

class LogoutConfigurationTest
{
    private LogoutConfiguration $configuration1;
    private LogoutConfiguration $configuration2;

    public function __construct()
    {
        $xml1 = simplexml_load_string(
            '
<security>
    <authentication>
        <form>
            <logout page="test" target="me"/>  
        </form>
    </authentication>
</security>'
        );
        $this->configuration1 = new LogoutConfiguration($xml1->authentication->form);
        $xml2 = simplexml_load_string(
            '
<security>
    <authentication>
        <form>
        </form>
    </authentication>
</security>'
        );
        $this->configuration2 = new LogoutConfiguration($xml2->authentication->form);
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
