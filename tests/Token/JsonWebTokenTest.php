<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\WebSecurity\Token\JsonWebToken;
use Lucinda\WebSecurity\Token\JsonWebTokenPayload;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Strings;

class JsonWebTokenTest
{
    private JsonWebToken $object;
    private ?string $value = null;

    public function __construct()
    {
        $this->object = new JsonWebToken((new SaltGenerator(12))->getSalt());
    }

    public function encode()
    {
        $payload = new JsonWebTokenPayload();
        $payload->setApplicationId(123);
        $this->value = $this->object->encode($payload);
        return (new Strings($this->value))->assertNotEmpty();
    }


    public function decode()
    {
        $payload = new JsonWebTokenPayload();
        $payload->setApplicationId(123);
        return (new Arrays($this->object->decode($this->value)->toArray()))->assertEquals($payload->toArray());
    }
}
