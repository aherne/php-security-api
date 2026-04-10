<?php

namespace Test\Lucinda\WebSecurity\Authentication\Form;

use Lucinda\WebSecurity\Authentication\Form\FormRequestValidator;
use Lucinda\WebSecurity\Request;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Strings;

class FormRequestValidatorTest
{
    private \SimpleXMLElement $xml;

    public function __construct()
    {
        $this->xml = simplexml_load_string(
            '
<security>
    <authentication>
        <form/>
    </authentication>
</security>'
        );
    }


    public function login()
    {
        $result = [];

        $request = new Request();

        $request->setUri("asdf");
        $request->setMethod("GET");
        $validator = new FormRequestValidator($this->xml, $request);
        $login = $validator->login();
        $result[] = (new Booleans($login === null))->assertTrue("check not login");

        $request->setUri("login");
        $request->setMethod("POST");
        $request->setParameters(["username"=>"test", "password"=>"me"]);
        $validator = new FormRequestValidator($this->xml, $request);
        $login = $validator->login();
        $result[] = (new Strings($login->getDestinationPage()))->assertEquals("index", "check login");

        return $result;
    }


    public function logout()
    {
        $result = [];

        $request = new Request();

        $request->setUri("asdf");
        $validator = new FormRequestValidator($this->xml, $request);
        $logout = $validator->logout();
        $result[] = (new Booleans($logout === null))->assertTrue("check not logout");

        $request->setUri("logout");
        $validator = new FormRequestValidator($this->xml, $request);
        $logout = $validator->logout();
        $result[] = (new Strings($logout->getDestinationPage()))->assertEquals("login", "check logout");

        return $result;
    }
}
