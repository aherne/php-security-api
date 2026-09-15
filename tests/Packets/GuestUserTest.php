<?php

namespace Test\Lucinda\WebSecurity\Packets;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Packets\GuestUser;
use Lucinda\WebSecurity\Packets\Packet;
use Test\Lucinda\WebSecurity\Support\PacketTestCase;

final class GuestUserTest extends PacketTestCase
{
    protected function packet(): Packet
    {
        return new GuestUser("csrf-token");
    }

    public function getCsrfToken()
    {
        $packet = new GuestUser("csrf-token");

        return (new Strings($packet->getCsrfToken()))->assertEquals("csrf-token");
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
