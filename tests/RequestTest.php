<?php

namespace Test\Lucinda\WebSecurity;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Request;

final class RequestTest
{
    private function request(): Request
    {
        $request = new Request();
        $request->setUri("account");
        $request->setContextPath("/application/");
        $request->setIpAddress("192.0.2.10");
        $request->setMethod("POST");
        $request->setParameters(["field" => "value"]);
        $request->setAccessToken("access-token");

        return $request;
    }

    public function setUri()
    {
        $request = $this->request();

        return (new Strings($request->getUri()))->assertEquals("account");
    }

    public function setContextPath()
    {
        $request = $this->request();

        return (new Strings($request->getContextPath()))->assertEquals("/application/");
    }

    public function setIpAddress()
    {
        $request = $this->request();

        return (new Strings($request->getIpAddress()))->assertEquals("192.0.2.10");
    }

    public function setMethod()
    {
        $request = $this->request();

        return (new Strings($request->getMethod()))->assertEquals("POST");
    }

    public function setParameters()
    {
        $request = $this->request();

        return (new Arrays($request->getParameters()))->assertIdentical(["field" => "value"]);
    }

    public function setAccessToken()
    {
        $request = $this->request();

        return (new Strings($request->getAccessToken()))->assertEquals("access-token");
    }

    public function getUri()
    {
        return $this->setUri();
    }

    public function getContextPath()
    {
        return $this->setContextPath();
    }

    public function getIpAddress()
    {
        return $this->setIpAddress();
    }

    public function getMethod()
    {
        return $this->setMethod();
    }

    public function getParameters()
    {
        return $this->setParameters();
    }

    public function getAccessToken()
    {
        return $this->setAccessToken();
    }
}
