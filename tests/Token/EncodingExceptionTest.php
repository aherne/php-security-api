<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Token\EncodingException;
use Lucinda\WebSecurity\Token\Encryption;
use Lucinda\WebSecurity\Token\SynchronizerToken;

final class EncodingExceptionTest
{
    public function malformedEnvelope()
    {
        try {
            (new Encryption("shared-secret"))->decrypt("not-an-envelope");
        } catch (EncodingException $exception) {
            return (new Objects($exception))->assertInstanceOf(EncodingException::class);
        }

        throw new \RuntimeException("Malformed envelope did not produce EncodingException");
    }

    public function invalidJsonEncoding()
    {
        $invalidUtf8 = "\xB1\x31";

        try {
            (new SynchronizerToken("127.0.0.1", "shared-secret"))->encode($invalidUtf8);
        } catch (EncodingException $exception) {
            return (new Objects($exception))->assertInstanceOf(EncodingException::class);
        }

        throw new \RuntimeException("Invalid JSON input did not produce EncodingException");
    }

    public function invalidJsonDecoding()
    {
        $encoded = (new Encryption("shared-secret"))->encrypt("not-json");

        try {
            (new SynchronizerToken("127.0.0.1", "shared-secret"))->decode($encoded);
        } catch (EncodingException $exception) {
            return (new Objects($exception))->assertInstanceOf(EncodingException::class);
        }

        throw new \RuntimeException("Invalid encoded JSON did not produce EncodingException");
    }
}
