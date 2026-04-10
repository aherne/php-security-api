<?php

namespace Test\Lucinda\WebSecurity;

use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Authentication\OAuth2\Exception as OAuth2Exception;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\SecurityPacket;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\WebSecurity\Wrapper;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockOauth2Driver;

class WrapperTest
{
    private \SimpleXMLElement $xml_dao_dao;
    private \SimpleXMLElement $xml_dao_xml;
    private \SimpleXMLElement $xml_xml_dao;
    private \SimpleXMLElement $xml_xml_xml;
    private \SimpleXMLElement $xml_oauth2_dao;
    private \SimpleXMLElement $xml_oauth2_xml;

    public function __construct()
    {
        $secret = (new SaltGenerator(10))->getSalt();
        $this->xml_dao_dao = \simplexml_load_string(
            '
<xml>
    <security>
        <csrf secret="'.$secret.'"/>
        <persistence>
            <synchronizer_token secret="'.$secret.'"/>
        </persistence>
        <authentication>
            <form dao="Test\Lucinda\WebSecurity\mocks\Authentication\MockUsersAuthentication" throttler="Test\Lucinda\WebSecurity\mocks\Authentication\MockLoginThrottler"/>
        </authentication>
        <authorization>
            <by_dao page_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO" user_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO"/>
        </authorization>
    </security>
</xml>
'
        );
        $this->xml_dao_xml = \simplexml_load_string(
            '
<xml>
    <security>
        <csrf secret="'.$secret.'"/>
        <persistence>
            <synchronizer_token secret="'.$secret.'"/>
        </persistence>
        <authentication>
            <form dao="Test\Lucinda\WebSecurity\mocks\Authentication\MockUsersAuthentication" throttler="Test\Lucinda\WebSecurity\mocks\Authentication\MockLoginThrottler"/>
        </authentication>
        <authorization>
            <by_route/>
        </authorization>
    </security>
    <routes>
        <route id="login" roles="GUEST,USER"/>
        <route id="index" roles="USER"/>
        <route id="logout" roles="USER,ADMINISTRATOR"/>
        <route id="administration" roles="ADMINISTRATOR"/>
    </routes>
</xml>
'
        );
        $this->xml_xml_dao = \simplexml_load_string(
            '
<xml>
    <security>
        <csrf secret="'.$secret.'"/>
        <persistence>
            <synchronizer_token secret="'.$secret.'"/>
        </persistence>
        <authentication>
            <form throttler="Test\Lucinda\WebSecurity\mocks\Authentication\MockLoginThrottler"/>
        </authentication>
        <authorization>
            <by_dao page_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO" user_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO"/>
        </authorization>
    </security>
    <users roles="GUEST">
        <user id="1" username="test" password="'.password_hash("me", PASSWORD_BCRYPT).'"/>
    </users>
</xml>
'
        );
        $this->xml_xml_xml = \simplexml_load_string(
            '
<xml>
    <security>
        <csrf secret="'.$secret.'"/>
        <persistence>
            <synchronizer_token secret="'.$secret.'"/>
        </persistence>
        <authentication>
            <form throttler="Test\Lucinda\WebSecurity\mocks\Authentication\MockLoginThrottler"/>
        </authentication>
        <authorization>
            <by_route/>
        </authorization>
    </security>
    <users roles="GUEST">
        <user id="1" username="test" password="'.password_hash("me", PASSWORD_BCRYPT).'" roles="USER"/>
    </users>
    <routes>
        <route id="login" roles="GUEST,USER"/>
        <route id="index" roles="USER"/>
        <route id="logout" roles="USER,ADMINISTRATOR"/>
        <route id="administration" roles="ADMINISTRATOR"/>
    </routes>
</xml>
'
        );
        $this->xml_oauth2_dao = \simplexml_load_string(
            '
<xml>
    <security>
        <csrf secret="'.$secret.'"/>
        <persistence>
            <synchronizer_token secret="'.$secret.'"/>
        </persistence>
        <authentication>
            <oauth2 dao="Test\Lucinda\WebSecurity\mocks\Authentication\MockVendorAuthenticationDAO"/>
        </authentication>
        <authorization>
            <by_dao page_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO" user_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO"/>
        </authorization>
    </security>
</xml>
'
        );
        $this->xml_oauth2_xml = \simplexml_load_string(
            '
<xml>
    <security>
        <csrf secret="'.$secret.'"/>
        <persistence>
            <synchronizer_token secret="'.$secret.'"/>
        </persistence>
        <authentication>
            <oauth2 dao="Test\Lucinda\WebSecurity\mocks\Authentication\MockVendorAuthenticationDAO"/>
        </authentication>
        <authorization>
            <by_route/>
        </authorization>
    </security>
    <routes>
        <route id="login" roles="GUEST,USER"/>
        <route id="login/facebook" roles="GUEST"/>
        <route id="index" roles="USER"/>
        <route id="logout" roles="USER,ADMINISTRATOR"/>
        <route id="administration" roles="ADMINISTRATOR"/>
    </routes>
</xml>
'
        );
    }

    public function getUserID(): array
    {
        $results = [];

        foreach (["dao_dao", "dao_xml", "xml_xml", "xml_dao"] as $name) {
            $results = array_merge($results, $this->testNormal($name));
        }

        foreach (["oauth2_dao", "oauth2_xml"] as $name) {
            $results = array_merge($results, $this->testOAuth2($name));
        }

        return $results;
    }

    public function getCsrfToken(): Result
    {
        $wrapper = new Wrapper($this->xml_dao_dao, $this->getRequest("login"));
        return (new Strings($wrapper->getCsrfToken()))->assertNotEmpty("wrapper generates csrf token");
    }

    public function getAccessToken(): array
    {
        $results = [];

        $wrapper = new Wrapper($this->xml_dao_dao, $this->getRequest("login"));
        $results[] = (new Booleans($wrapper->getAccessToken() === null))->assertTrue("getAccessToken returns null before login");

        $accessToken = "";
        try {
            new Wrapper(
                $this->xml_dao_dao,
                $this->getRequest("login", "POST", ["username" => "test", "password" => "me", "csrf" => $wrapper->getCsrfToken()])
            );
        } catch (SecurityPacket $packet) {
            $accessToken = $packet->getAccessToken() ?? "";
        }

        $wrapper = new Wrapper($this->xml_dao_dao, $this->getRequest("index", "GET", [], $accessToken));
        $results[] = (new Strings($wrapper->getAccessToken() ?? ""))->assertEquals($accessToken, "getAccessToken returns active token after login");

        return $results;
    }

    private function testNormal(string $name): array
    {
        $results = [];
        $xml = $this->{"xml_".$name};

        $results[] = $this->assertSecurityPacketStatus(
            fn() => new Wrapper($xml, $this->getRequest("asdf")),
            "not_found",
            "unknown route is rejected: ".$name
        );

        $wrapper = new Wrapper($xml, $this->getRequest("login"));
        $results[] = (new Booleans($wrapper->getUserID() === null))->assertTrue("guest user id is null on login page: ".$name);
        $csrfToken = $wrapper->getCsrfToken();

        $results[] = $this->assertSecurityPacketStatus(
            fn() => new Wrapper($xml, $this->getRequest("login", "POST", ["username" => "test", "password" => "me1", "csrf" => $csrfToken])),
            "login_failed",
            "invalid form credentials fail: ".$name
        );

        $accessToken = "";
        try {
            new Wrapper($xml, $this->getRequest("login", "POST", ["username" => "test", "password" => "me", "csrf" => $csrfToken]));
            $results[] = (new Booleans(false))->assertTrue("valid form login triggers packet: ".$name);
        } catch (SecurityPacket $packet) {
            $accessToken = $packet->getAccessToken() ?? "";
            $results[] = (new Strings($packet->getStatus()))->assertEquals("login_ok", "valid form login succeeds: ".$name);
            $results[] = (new Strings($accessToken))->assertNotEmpty("valid form login returns access token: ".$name);
        }

        $wrapper = new Wrapper($xml, $this->getRequest("index", "GET", [], $accessToken));
        $results[] = (new Integers((int) $wrapper->getUserID()))->assertEquals(1, "authenticated user reaches index: ".$name);

        $results[] = $this->assertSecurityPacketStatus(
            fn() => new Wrapper($xml, $this->getRequest("administration", "GET", [], $accessToken)),
            "forbidden",
            "authenticated user is forbidden on administration: ".$name
        );

        $results[] = $this->assertSecurityPacketStatus(
            fn() => new Wrapper($xml, $this->getRequest("logout", "GET", ["csrf" => $csrfToken], $accessToken)),
            "logout_ok",
            "authenticated logout succeeds: ".$name
        );

        $results[] = $this->assertSecurityPacketStatus(
            fn() => new Wrapper($xml, $this->getRequest("logout", "GET", ["csrf" => $csrfToken])),
            "logout_failed",
            "logout fails after user is already logged out: ".$name
        );

        $results[] = $this->assertSecurityPacketStatus(
            fn() => new Wrapper($xml, $this->getRequest("index")),
            "unauthorized",
            "guest access to index is unauthorized: ".$name
        );

        return $results;
    }

    private function testOAuth2(string $name): array
    {
        $results = [];
        $drivers = [new MockOauth2Driver("Facebook")];
        $xml = $this->{"xml_".$name};

        $results[] = $this->assertSecurityPacketStatus(
            fn() => new Wrapper($xml, $this->getRequest("asdf"), $drivers),
            "not_found",
            "unknown route is rejected for oauth2: ".$name
        );

        $wrapper = new Wrapper($xml, $this->getRequest("login"), $drivers);
        $results[] = (new Booleans($wrapper->getUserID() === null))->assertTrue("guest user id is null on oauth2 login page: ".$name);
        $csrfToken = $wrapper->getCsrfToken();

        try {
            new Wrapper($xml, $this->getRequest("login/facebook"), $drivers);
            $results[] = (new Booleans(false))->assertTrue("oauth2 login redirects for authorization code: ".$name);
        } catch (SecurityPacket $packet) {
            $results[] = (new Strings($packet->getStatus()))->assertEquals("redirect", "oauth2 login returns redirect packet: ".$name);
            $results[] = (new Strings($packet->getCallback()))->assertEquals("qwerty", "oauth2 login returns provider callback: ".$name);
        }

        try {
            new Wrapper($xml, $this->getRequest("login/facebook", "GET", ["error" => "asdfg"]), $drivers);
            $results[] = (new Booleans(false))->assertTrue("oauth2 provider error throws exception: ".$name);
        } catch (OAuth2Exception $exception) {
            $results[] = (new Objects($exception))->assertInstanceOf(OAuth2Exception::class, "oauth2 provider error is surfaced: ".$name);
        }

        $accessToken = "";
        try {
            new Wrapper($xml, $this->getRequest("login/facebook", "GET", ["code" => "qwerty", "state" => $csrfToken]), $drivers);
            $results[] = (new Booleans(false))->assertTrue("oauth2 callback returns login packet: ".$name);
        } catch (SecurityPacket $packet) {
            $accessToken = $packet->getAccessToken() ?? "";
            $results[] = (new Strings($packet->getStatus()))->assertEquals("login_ok", "oauth2 callback login succeeds: ".$name);
            $results[] = (new Strings($accessToken))->assertNotEmpty("oauth2 callback returns access token: ".$name);
        }

        $wrapper = new Wrapper($xml, $this->getRequest("index", "GET", [], $accessToken), $drivers);
        $results[] = (new Integers((int) $wrapper->getUserID()))->assertEquals(1, "oauth2-authenticated user reaches index: ".$name);

        $results[] = $this->assertSecurityPacketStatus(
            fn() => new Wrapper($xml, $this->getRequest("administration", "GET", [], $accessToken), $drivers),
            "forbidden",
            "oauth2-authenticated user is forbidden on administration: ".$name
        );

        $results[] = $this->assertSecurityPacketStatus(
            fn() => new Wrapper($xml, $this->getRequest("logout", "GET", [], $accessToken), $drivers),
            "logout_ok",
            "oauth2 logout succeeds: ".$name
        );

        $results[] = $this->assertSecurityPacketStatus(
            fn() => new Wrapper($xml, $this->getRequest("logout"), $drivers),
            "logout_failed",
            "oauth2 logout fails after session is cleared: ".$name
        );

        $results[] = $this->assertSecurityPacketStatus(
            fn() => new Wrapper($xml, $this->getRequest("index"), $drivers),
            "unauthorized",
            "guest access to index stays unauthorized after oauth2 logout: ".$name
        );

        return $results;
    }

    private function assertSecurityPacketStatus(callable $callback, string $expectedStatus, string $message): Result
    {
        try {
            $callback();
            return (new Booleans(false))->assertTrue($message);
        } catch (SecurityPacket $packet) {
            return (new Strings($packet->getStatus()))->assertEquals($expectedStatus, $message);
        }
    }

    private function getRequest(string $uri, string $method="GET", array $parameters=[], string $accessToken=""): Request
    {
        $request = new Request();
        $request->setUri($uri);
        $request->setMethod($method);
        $request->setParameters($parameters);
        $request->setContextPath("");
        $request->setIpAddress("127.0.0.1");
        $request->setAccessToken($accessToken);
        return $request;
    }
}
