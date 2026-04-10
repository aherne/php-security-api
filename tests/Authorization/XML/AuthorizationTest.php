<?php

namespace Test\Lucinda\WebSecurity\Authorization\XML;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Authorization\Result as AuthorizationResult;
use Lucinda\WebSecurity\Authorization\ResultStatus;
use Lucinda\WebSecurity\Authorization\XML\Authorization;
use Lucinda\WebSecurity\Authorization\XML\UserAuthorizationXML;

class AuthorizationTest
{
    private \SimpleXMLElement $xml;

    public function __construct()
    {
        $this->xml = \simplexml_load_string(
            '
<xml>
    <users roles="GUEST">
        <user id="1" roles="USER"/>
    </users>
    <routes>
        <route id="login" roles="GUEST,USER"/>
        <route id="index" roles="USER"/>
        <route id="logout" roles="USER,ADMINISTRATOR"/>
        <route id="administration" roles="ADMINISTRATOR"/>
    </routes>
</xml>'
        );
    }

    public function authorize()
    {
        $authorization = new Authorization("login", "index");

        return [
            (new Strings($this->test($authorization, "asdf", null)->getStatus()->name))->assertEquals(ResultStatus::NOT_FOUND->name, "test path not found"),
            (new Strings($this->test($authorization, "login", null)->getStatus()->name))->assertEquals(ResultStatus::OK->name, "guest allowed to login"),
            (new Strings($this->test($authorization, "index", null)->getStatus()->name))->assertEquals(ResultStatus::UNAUTHORIZED->name, "guest unauthorized to index"),
            (new Strings($this->test($authorization, "index", 1)->getStatus()->name))->assertEquals(ResultStatus::OK->name, "user allowed to index"),
            (new Strings($this->test($authorization, "administration", 1)->getStatus()->name))->assertEquals(ResultStatus::FORBIDDEN->name, "user forbidden to administration"),
        ];
    }

    private function test(Authorization $authorization, string $url, ?int $userID): AuthorizationResult
    {
        return $authorization->authorize($this->xml, $url, $userID, new UserAuthorizationXML($this->xml));
    }
}
