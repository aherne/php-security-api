<?php

namespace Test\Lucinda\WebSecurity;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Packets\Security;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Lucinda\WebSecurity\Wrapper;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockLoginThrottler;

class WrapperTest
{
    private function xml(): \SimpleXMLElement
    {
        $secret = str_repeat("a", 32);
        return simplexml_load_string('
            <xml><security>
                <csrf secret="'.$secret.'"/>
                <persistence><synchronizer_token secret="'.$secret.'"/></persistence>
                <authentication>
                    <form dao="Test\Lucinda\WebSecurity\mocks\Authentication\MockUsersAuthentication">
                        <login page="login" target_success="index" target_failure="login_failed"/>
                        <logout page="logout" target_success="login" target_failure="logout_failed"/>
                    </form>
                </authentication>
                <authorization>
                    <by_dao
                        page_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO"
                        user_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO"
                        logged_in_callback="forbidden"
                        logged_out_callback="login"/>
                </authorization>
            </security></xml>
        ');
    }

    private function request(string $uri, string $method="GET", array $parameters=[], string $token=""): Request
    {
        $request = new Request();
        $request->setUri($uri);
        $request->setMethod($method);
        $request->setParameters($parameters);
        $request->setContextPath("");
        $request->setIpAddress("127.0.0.1");
        $request->setAccessToken($token);
        return $request;
    }

    private function login(): Wrapper
    {
        $xml = $this->xml();
        $throttler = new MockLoginThrottler();
        $guest = new Wrapper($xml, $this->request("login"), [], $throttler);
        return new Wrapper($xml, $this->request("login", "POST", [
            "username"=>"test", "password"=>"me", "csrf"=>$guest->getCsrfToken()
        ]), [], $throttler);
    }

    public function getOutcome(): array
    {
        $wrapper = $this->login();
        $outcome = $wrapper->getOutcome();
        return [
            (new Objects($outcome))->assertInstanceOf(Security::class),
            (new Booleans($outcome->getStatus() === ResultStatus::LOGIN_OK))->assertTrue(),
            (new Strings($outcome->getCallback() ?? ""))->assertEquals("/index")
        ];
    }

    public function getUserID()
    {
        return (new Integers((int)$this->login()->getUserID()))->assertEquals(1);
    }

    public function getCsrfToken()
    {
        $wrapper = new Wrapper($this->xml(), $this->request("login"), [], new MockLoginThrottler());
        return (new Strings($wrapper->getCsrfToken()))->assertNotEmpty();
    }

    public function getAccessToken()
    {
        return (new Strings($this->login()->getAccessToken() ?? ""))->assertNotEmpty();
    }
}
