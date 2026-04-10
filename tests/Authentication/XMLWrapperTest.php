<?php

namespace Test\Lucinda\WebSecurity\Authentication;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Authentication\Form\Exception as FormException;
use Lucinda\WebSecurity\Authentication\Result;
use Lucinda\WebSecurity\Authentication\ResultStatus;
use Lucinda\WebSecurity\Authentication\XMLWrapper;
use Lucinda\WebSecurity\CsrfTokenDetector;
use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Token\Exception as TokenException;
use Lucinda\WebSecurity\Token\SaltGenerator;

class XMLWrapperTest
{
    private \SimpleXMLElement $xml;
    private SynchronizerTokenPersistenceDriver $persistenceDriver;
    private CsrfTokenDetector $csrfTokenDetector;

    public function __construct()
    {
        $secret = (new SaltGenerator(10))->getSalt();
        $xml = \simplexml_load_string(
            '
<xml>
    <security>
        <csrf secret="'.$secret.'"/>
        <authentication>
            <form throttler="Test\Lucinda\WebSecurity\mocks\Authentication\MockLoginThrottler"/>
        </authentication>
    </security>
    <users>
        <user id="1" username="test" password="'.password_hash("me", PASSWORD_BCRYPT).'"/>
    </users>
</xml>'
        );
        $this->xml = $xml->security;
        $this->persistenceDriver = new SynchronizerTokenPersistenceDriver($secret, "127.0.0.1");
        $this->csrfTokenDetector = new CsrfTokenDetector($this->xml, "127.0.0.1");
    }

    public function getResult()
    {
        $results = [];

        $request = new Request();

        $request->setUri("asd");
        $wrapper = new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
        $results[] = (new Booleans($wrapper->getResult() === null))->assertTrue("tested no login");

        $request->setUri("login");
        $request->setMethod("GET");
        $wrapper = new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
        $results[] = (new Booleans($wrapper->getResult() === null))->assertTrue("tested login get");

        $request->setMethod("POST");
        $request->setParameters(["user"=>"test", "password"=>"me"]);
        try {
            new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
            $results[] = (new Booleans(false))->assertTrue("tested login post: missing params");
        } catch (FormException $e) {
            $results[] = (new Strings($e->getMessage()))->assertEquals("POST parameter missing: username", "tested login post: missing params");
        }

        $request->setParameters(["username"=>"test", "password"=>"me"]);
        try {
            new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
            $results[] = (new Booleans(false))->assertTrue("tested login post: missing csrf token");
        } catch (TokenException $e) {
            $results[] = (new Strings($e->getMessage()))->assertEquals("CSRF token is invalid or missing!", "tested login post: missing csrf token");
        }

        $request->setParameters(["username"=>"test", "password"=>"me", "csrf"=>"asdfgh"]);
        try {
            new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
            $results[] = (new Booleans(false))->assertTrue("tested login post: bad csrf token");
        } catch (TokenException $e) {
            $results[] = (new Strings($e->getMessage()))->assertEquals("CSRF token is invalid or missing!", "tested login post: bad csrf token");
        }

        $request->setParameters(["username"=>"test", "password"=>"me", "csrf"=>$this->csrfTokenDetector->generate(0)]);
        $wrapper = new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
        $results[] = (new Objects($wrapper->getResult()))->assertInstanceOf(Result::class, "xml wrapper returns a result for successful login");
        $results[] = (new Strings($wrapper->getResult()->getStatus()->name))->assertEquals(ResultStatus::LOGIN_OK->name, "tested login post: success");

        $request->setParameters(["username"=>"test", "password"=>"mex", "csrf"=>$this->csrfTokenDetector->generate(0)]);
        $wrapper = new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
        $results[] = (new Strings($wrapper->getResult()->getStatus()->name))->assertEquals(ResultStatus::LOGIN_FAILED->name, "tested login post: failure");

        $request->setUri("logout");
        $request->setParameters(["csrf"=>$this->csrfTokenDetector->generate(0)]);
        $wrapper = new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
        $results[] = (new Strings($wrapper->getResult()->getStatus()->name))->assertEquals(ResultStatus::LOGOUT_OK->name, "tested logout: status");
        $results[] = (new Booleans($this->persistenceDriver->load() === null))->assertTrue("tested logout: persistence");

        return $results;
    }
}
