<?php

namespace Test\Lucinda\WebSecurity\Authentication;

use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\CsrfTokenDetector;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\WebSecurity\Request;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\Form\Exception as FormException;
use Lucinda\WebSecurity\Token\Exception as TokenException;
use Lucinda\WebSecurity\Authentication\XMLWrapper;
use Lucinda\WebSecurity\Authentication\ResultStatus;

class XMLWrapperTest
{
    private $xml;
    private $persistenceDriver;
    private $csrfTokenDetector;

    public function __construct()
    {
        $secret = (new SaltGenerator(10))->getSalt();
        $xml = simplexml_load_string(
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
        $results[] = new Result($wrapper->getResult()===null, "tested no login");

        $request->setUri("login");
        $request->setMethod("GET");
        $wrapper = new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
        $results[] = new Result($wrapper->getResult()===null, "tested login get");

        $request->setMethod("POST");
        $request->setParameters(["user"=>"test", "password"=>"me"]);
        try {
            new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
            $results[] = new Result(false, "tested login post: missing params");
        } catch (FormException $e) {
            $results[] = new Result($e->getMessage()=="POST parameter missing: username", "tested login post: missing params");
        }

        $request->setParameters(["username"=>"test", "password"=>"me"]);
        try {
            new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
            $results[] = new Result(false, "tested login post: missing csrf token");
        } catch (TokenException $e) {
            $results[] = new Result($e->getMessage()=="CSRF token is invalid or missing!", "tested login post: missing csrf token");
        }

        $request->setParameters(["username"=>"test", "password"=>"me", "csrf"=>"asdfgh"]);
        try {
            new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
            $results[] = new Result(false, "tested login post: bad csrf token");
        } catch (TokenException $e) {
            $results[] = new Result($e->getMessage()=="CSRF token is invalid or missing!", "tested login post: bad csrf token");
        }

        $request->setParameters(["username"=>"test", "password"=>"me", "csrf"=>$this->csrfTokenDetector->generate(0)]);
        $wrapper = new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
        $results[] = new Result($wrapper->getResult()->getStatus()==ResultStatus::LOGIN_OK, "tested login post: success");

        $request->setParameters(["username"=>"test", "password"=>"mex", "csrf"=>$this->csrfTokenDetector->generate(0)]);
        $wrapper = new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
        $results[] = new Result($wrapper->getResult()->getStatus()==ResultStatus::LOGIN_FAILED, "tested login post: failure");

        $request->setUri("logout");
        $wrapper = new XMLWrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver]);
        $results[] = new Result($wrapper->getResult()->getStatus()==ResultStatus::LOGOUT_OK, "tested logout: status");
        $results[] = new Result($this->persistenceDriver->load()==null, "tested logout: persistence");

        return $results;
    }
}
