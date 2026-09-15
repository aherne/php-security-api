<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Token\SynchronizerToken;

final class SynchronizerTokenTest
{
    public function encode()
    {
        $encoded = (new SynchronizerToken("127.0.0.1", "shared-secret"))->encode(7);

        return (new Strings($encoded))->assertContains("v2.");
    }

    public function decode()
    {
        $token = new SynchronizerToken("127.0.0.1", "shared-secret");
        $encoded = $token->encode(7);
        $decoded = $token->decode($encoded);

        return (new Integers($decoded))->assertEquals(7);
    }
}
