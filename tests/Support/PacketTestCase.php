<?php

namespace Test\Lucinda\WebSecurity\Support;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Packets\Packet;
use Lucinda\WebSecurity\Security\FailureReason;

abstract class PacketTestCase
{
    abstract protected function packet(): Packet;

    protected function assertUserID()
    {
        $packet = $this->packet();
        $packet->setUserID(42);

        return (new Integers($packet->getUserID()))->assertEquals(42);
    }

    protected function assertCallback()
    {
        $packet = $this->packet();
        $packet->setCallback("/next");

        return (new Strings($packet->getCallback()))->assertEquals("/next");
    }

    protected function assertFailureReason()
    {
        $packet = $this->packet();
        $packet->setFailureReason(FailureReason::FORM_CREDENTIALS_REJECTED);
        $actual = $packet->getFailureReason();

        return (new Arrays([$actual]))->assertIdentical([FailureReason::FORM_CREDENTIALS_REJECTED]);
    }

    protected function assertAccessToken()
    {
        $packet = $this->packet();
        $packet->setAccessToken("access-token");

        return (new Strings($packet->getAccessToken()))->assertEquals("access-token");
    }
}
