<?php

namespace Test\Lucinda\WebSecurity\Packets;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Packets\Packet;
use Lucinda\WebSecurity\Packets\Throttling;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Test\Lucinda\WebSecurity\Support\PacketTestCase;

final class ThrottlingTest extends PacketTestCase
{
    protected function packet(): Packet
    {
        return new Throttling(ResultStatus::LOGIN_THROTTLED);
    }

    public function setStatus()
    {
        $packet = new Throttling(ResultStatus::LOGIN_THROTTLED);

        return (new Arrays([$packet->getStatus()]))->assertIdentical([ResultStatus::LOGIN_THROTTLED]);
    }

    public function getStatus()
    {
        return $this->setStatus();
    }

    public function setUserID()
    {
        return $this->assertUserID();
    }

    public function getUserID()
    {
        return $this->assertUserID();
    }

    public function setCallback()
    {
        return $this->assertCallback();
    }

    public function getCallback()
    {
        return $this->assertCallback();
    }

    public function setFailureReason()
    {
        return $this->assertFailureReason();
    }

    public function getFailureReason()
    {
        return $this->assertFailureReason();
    }

    public function setAccessToken()
    {
        return $this->assertAccessToken();
    }

    public function getAccessToken()
    {
        return $this->assertAccessToken();
    }
}
