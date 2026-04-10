<?php

namespace Test\Lucinda\WebSecurity\Authentication;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Authentication\OAuth2Wrapper;
use Lucinda\WebSecurity\Authentication\ResultStatus;
use Lucinda\WebSecurity\CsrfTokenDetector;
use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Token\Exception as TokenException;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockOauth2Driver;

class OAuth2WrapperTest
{
    private \SimpleXMLElement $xml;
    private SynchronizerTokenPersistenceDriver $persistenceDriver;
    private MockOauth2Driver $oauth2Driver;
    private CsrfTokenDetector $csrfTokenDetector;

    public function __construct()
    {
        $secret = (new SaltGenerator(10))->getSalt();
        $this->xml = \simplexml_load_string(
            '
<security>
    <csrf secret="'.$secret.'"/>
    <authentication>
        <oauth2 dao="Test\Lucinda\WebSecurity\mocks\Authentication\MockVendorAuthenticationDAO"/>
    </authentication>
</security>'
        );
        $this->persistenceDriver = new SynchronizerTokenPersistenceDriver($secret, "127.0.0.1");
        $this->oauth2Driver = new MockOauth2Driver("Facebook");
        $this->csrfTokenDetector = new CsrfTokenDetector($this->xml, "127.0.0.1");
    }

    public function getResult()
    {
        $results = [];

        $request = new Request();

        $request->setUri("asd");
        $wrapper = new OAuth2Wrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver], [$this->oauth2Driver]);
        $results[] = (new Booleans($wrapper->getResult() === null))->assertTrue("tested no login");

        $request->setUri("login/facebook");
        $wrapper = new OAuth2Wrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver], [$this->oauth2Driver]);
        $results[] = (new Strings($wrapper->getResult()->getStatus()->name))->assertEquals(ResultStatus::DEFERRED->name, "tested login - authorization code");

        $request->setParameters(["code"=>"qwerty"]);
        try {
            new OAuth2Wrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver], [$this->oauth2Driver]);
            $results[] = (new Booleans(false))->assertTrue("tested login + authorization code: missing csrf token");
        } catch (TokenException $e) {
            $results[] = (new Strings($e->getMessage()))->assertEquals("CSRF token is invalid or missing!", "tested login + authorization code: missing csrf token");
        }

        $request->setParameters(["code"=>"qwerty", "state"=>$this->csrfTokenDetector->generate(0)]);
        $wrapper = new OAuth2Wrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver], [$this->oauth2Driver]);
        $results[] = (new Strings($wrapper->getResult()->getStatus()->name))->assertEquals(ResultStatus::LOGIN_OK->name, "tested login + authorization code: successful");

        $request->setUri("logout");
        $request->setParameters(["csrf"=>$this->csrfTokenDetector->generate(0)]);
        $wrapper = new OAuth2Wrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver], [$this->oauth2Driver]);
        $results[] = (new Strings($wrapper->getResult()->getStatus()->name))->assertEquals(ResultStatus::LOGOUT_OK->name, "tested logout: status");
        $results[] = (new Booleans($this->persistenceDriver->load() === null))->assertTrue("tested logout: persistence");

        return $results;
    }
}
