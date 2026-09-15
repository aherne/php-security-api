<?php

namespace Test\Lucinda\WebSecurity\Packets;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Packets\Packet;
use Lucinda\WebSecurity\Packets\Security;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Test\Lucinda\WebSecurity\Support\PacketTestCase;

final class SecurityTest extends PacketTestCase
{
    protected function packet(): Packet
    {
        return new Security(ResultStatus::LOGIN_FAILED);
    }

    public function setStatus()
    {
        $packet = new Security(ResultStatus::LOGIN_FAILED);
        $packet->setStatus(ResultStatus::IDENTITY_VERIFIED);

        return (new Arrays([$packet->getStatus()]))->assertIdentical([ResultStatus::IDENTITY_VERIFIED]);
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
