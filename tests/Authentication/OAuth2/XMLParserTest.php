<?php

namespace Test\Lucinda\WebSecurity\Authentication\OAuth2;

use Lucinda\WebSecurity\Authentication\OAuth2\XMLParser;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Strings;

class XMLParserTest
{
    private XMLParser $parser;

    public function __construct()
    {
        $xml = simplexml_load_string(
            '
<security>
    <authentication>
        <oauth2/>
    </authentication>
</security>'
        );
        $this->parser = new XMLParser($xml);
    }

    public function getLoginCallback()
    {
        return (new Strings($this->parser->getLoginCallback()))->assertEquals("login");
    }


    public function getLogoutCallback()
    {
        return (new Strings($this->parser->getLogoutCallback()))->assertEquals("logout");
    }


    public function getTargetCallback()
    {
        return (new Strings($this->parser->getTargetCallback()))->assertEquals("index");
    }
}
