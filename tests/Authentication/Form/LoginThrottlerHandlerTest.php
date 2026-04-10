<?php

namespace Test\Lucinda\WebSecurity\Authentication\Form;

use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Authentication\Form\LoginThrottlerHandler;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\OAuth2\AuthenticationResult;
use Lucinda\WebSecurity\Authentication\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockLoginThrottler;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;

class LoginThrottlerHandlerTest
{
    private $throttler;
    private $request;

    public function __construct()
    {
        $request = new Request();
        $request->setUri("login");
        $this->request = $request;

        $this->throttler = new MockLoginThrottler($request, "test");
    }

    public function start()
    {
        $handler = new LoginThrottlerHandler($this->throttler);
        $handler->end(new AuthenticationResult(ResultStatus::LOGIN_FAILED));
        return (new Integers($handler->start($this->request)->getTimePenalty()))->assertEquals(1);
    }


    public function end()
    {
        $handler = new LoginThrottlerHandler($this->throttler);

        $result = [];

        $handler->end(new AuthenticationResult(ResultStatus::LOGIN_FAILED));
        $handler->end(new AuthenticationResult(ResultStatus::LOGIN_FAILED));
        $result[] = (new Integers($handler->start($this->request)->getTimePenalty()))->assertEquals(9, "tested penalty incrementation");

        $handler->end(new AuthenticationResult(ResultStatus::LOGIN_OK));
        $result[] = (new Booleans($handler->start($this->request) === null))->assertTrue("tested penalty reset");

        return $result;
    }
}
