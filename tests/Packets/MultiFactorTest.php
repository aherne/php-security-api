<?php

namespace Test\Lucinda\WebSecurity\Packets;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Packets\MultiFactor;
use Lucinda\WebSecurity\Packets\Packet;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus;
use Test\Lucinda\WebSecurity\Support\PacketTestCase;

final class MultiFactorTest extends PacketTestCase
{
    protected function packet(): Packet
    {
        return new MultiFactor();
    }

    public function setStatus()
    {
        $packet = new MultiFactor();
        $packet->setStatus(ResultStatus::REQUIRED);

        return (new Arrays([$packet->getStatus()]))->assertIdentical([ResultStatus::REQUIRED]);
    }

    public function getStatus()
    {
        return $this->setStatus();
    }

    public function setSecret()
    {
        $packet = new MultiFactor();
        $packet->setSecret("BASE32SECRET");

        return (new Strings($packet->getSecret()))->assertEquals("BASE32SECRET");
    }

    public function getSecret()
    {
        return $this->setSecret();
    }

    public function setProvisioningURI()
    {
        $packet = new MultiFactor();
        $packet->setProvisioningURI("otpauth://totp/example");

        return (new Strings($packet->getProvisioningURI()))->assertEquals("otpauth://totp/example");
    }

    public function getProvisioningURI()
    {
        return $this->setProvisioningURI();
    }

    public function setValidUntil()
    {
        $packet = new MultiFactor();
        $packet->setValidUntil(1234567890);

        return (new Integers($packet->getValidUntil()))->assertEquals(1234567890);
    }

    public function getValidUntil()
    {
        return $this->setValidUntil();
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
