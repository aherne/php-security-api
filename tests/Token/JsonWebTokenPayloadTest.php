<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\WebSecurity\Token\JsonWebTokenPayload;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class JsonWebTokenPayloadTest
{
    private JsonWebTokenPayload $object;

    public function __construct()
    {
        $this->object = new JsonWebTokenPayload();
    }

    public function setIssuer()
    {
        $this->object->setIssuer("qwerty");
        return (new Strings($this->object->getIssuer()))->assertEquals("qwerty");
    }


    public function getIssuer()
    {
        return (new Strings($this->object->getIssuer()))->assertEquals("qwerty");
    }


    public function setSubject()
    {
        $this->object->setSubject(1);
        return (new Integers((int) $this->object->getSubject()))->assertEquals(1);
    }


    public function getSubject()
    {
        return (new Integers((int) $this->object->getSubject()))->assertEquals(1);
    }


    public function setAudience()
    {
        $this->object->setAudience("uiop");
        return (new Strings($this->object->getAudience()))->assertEquals("uiop");
    }


    public function getAudience()
    {
        return (new Strings($this->object->getAudience()))->assertEquals("uiop");
    }


    public function setEndTime()
    {
        $this->object->setEndTime(123);
        return (new Integers($this->object->getEndTime()))->assertEquals(123);
    }


    public function getEndTime()
    {
        return (new Integers($this->object->getEndTime()))->assertEquals(123);
    }


    public function setStartTime()
    {
        $this->object->setStartTime(456);
        return (new Integers($this->object->getStartTime()))->assertEquals(456);
    }


    public function getStartTime()
    {
        return (new Integers($this->object->getStartTime()))->assertEquals(456);
    }


    public function setIssuedTime()
    {
        $this->object->setIssuedTime(789);
        return (new Integers($this->object->getIssuedTime()))->assertEquals(789);
    }


    public function getIssuedTime()
    {
        return (new Integers($this->object->getIssuedTime()))->assertEquals(789);
    }


    public function setApplicationId()
    {
        $this->object->setApplicationId("zxcvb");
        return (new Strings((string) $this->object->getApplicationId()))->assertEquals("zxcvb");
    }


    public function getApplicationId()
    {
        return (new Strings((string) $this->object->getApplicationId()))->assertEquals("zxcvb");
    }


    public function setCustomClaim()
    {
        $this->object->setCustomClaim("x", "y");
        return (new Strings($this->object->getCustomClaim("x")))->assertEquals("y");
    }


    public function getCustomClaim()
    {
        return (new Strings($this->object->getCustomClaim("x")))->assertEquals("y");
    }


    public function toArray()
    {
        $data = ["iss"=>"a", "sub"=>"b", "aud"=>"c"];
        $object = new JsonWebTokenPayload($data);
        return (new Arrays($object->toArray()))->assertEquals($data);
    }
}
