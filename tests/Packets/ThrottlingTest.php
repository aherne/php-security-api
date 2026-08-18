<?php
namespace Test\Lucinda\WebSecurity\Packets;

use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Packets\Exception;
use Lucinda\WebSecurity\Packets\Throttling;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus as MultiFactorResultStatus;

class ThrottlingTest
{
    private function packet(): Throttling
    {
        return new Throttling(ResultStatus::LOGIN_THROTTLED);
    }

    public function setStatus()
    {
        $packet = $this->packet();
        $packet->setStatus(MultiFactorResultStatus::THROTTLED);

        return (new Booleans($packet->getStatus() === MultiFactorResultStatus::THROTTLED))->assertTrue();
    }

    public function getStatus()
    {
        return (new Booleans($this->packet()->getStatus() === ResultStatus::LOGIN_THROTTLED))->assertTrue();
    }

    public function setTimePenalty()
    {
        $packet = $this->packet();
        $packet->setTimePenalty(9);
        return (new Integers($packet->getTimePenalty()))->assertEquals(9);
    }

    public function getTimePenalty()
    {
        try {
            $this->packet()->getTimePenalty();
            return (new Booleans(false))->assertTrue();
        } catch (Exception $exception) {
            return (new Objects($exception))->assertInstanceOf(Exception::class);
        }
    }

    public function setUserID()
    {
        $packet = $this->packet();
        $packet->setUserID(7);
        return (new Integers((int) $packet->getUserID()))->assertEquals(7);
    }

    public function getUserID()
    {
        return (new Booleans($this->packet()->getUserID() === null))->assertTrue();
    }

    public function setCallback()
    {
        $packet = $this->packet();
        $packet->setCallback("wait");
        return (new Strings($packet->getCallback() ?? ""))->assertEquals("wait");
    }

    public function getCallback()
    {
        return (new Booleans($this->packet()->getCallback() === null))->assertTrue();
    }
    public function setAccessToken()
    {
    }
        

    public function getAccessToken()
    {
    }
        

}
