<?php

namespace Test\Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Persistence\SynchronizerToken;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class SynchronizerTokenTest
{
    private function configuration(): SynchronizerToken
    {
        return new SynchronizerToken(Fixture::node("synchronizer-token"));
    }

    public function getSecret()
    {
        return (new Strings($this->configuration()->getSecret()))->assertEquals("secret");
    }

    public function getRegenerationTime()
    {
        return (new Integers($this->configuration()->getRegenerationTime()))->assertEquals(90);
    }

    public function getExpirationTime()
    {
        return (new Integers($this->configuration()->getExpirationTime()))->assertEquals(3600);
    }
}
