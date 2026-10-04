<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Token\Encryption;
use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\ValidationException;

final class ValidationExceptionTest
{
    public function invalidDecodedPayload()
    {
        $encoded = (new Encryption("shared-secret"))->encrypt('{"uid":7}');

        try {
            (new SynchronizerToken("127.0.0.1", "shared-secret"))->decode($encoded);
        } catch (ValidationException $exception) {
            return (new Objects($exception))->assertInstanceOf(ValidationException::class);
        }

        throw new \RuntimeException("Invalid decoded payload did not produce ValidationException");
    }

    public function invalidSecurityContext()
    {
        $encoded = (new SynchronizerToken("127.0.0.1", "shared-secret"))->encode(7);

        try {
            (new SynchronizerToken("127.0.0.2", "shared-secret"))->decode($encoded);
        } catch (ValidationException $exception) {
            return (new Objects($exception))->assertInstanceOf(ValidationException::class);
        }

        throw new \RuntimeException("Invalid token security context did not produce ValidationException");
    }
}
