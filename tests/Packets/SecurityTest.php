<?php
namespace Test\Lucinda\WebSecurity\Packets;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Packets\Security;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;

class SecurityTest
{
    private function packet(): Security
    {
        return new Security(ResultStatus::LOGIN_FAILED);
    }

    public function setStatus()
    {
        $packet = $this->packet();
        $packet->setStatus(ResultStatus::LOGIN_OK);
        return (new Booleans($packet->getStatus() === ResultStatus::LOGIN_OK))->assertTrue();
    }

    public function getStatus()
    {
        return (new Booleans($this->packet()->getStatus() === ResultStatus::LOGIN_FAILED))->assertTrue();
    }

    public function setAccessToken()
    {
        $packet = $this->packet();
        $packet->setAccessToken("token");
        return (new Strings($packet->getAccessToken() ?? ""))->assertEquals("token");
    }

    public function getAccessToken()
    {
        return (new Booleans($this->packet()->getAccessToken() === null))->assertTrue();
    }

    public function setUserID()
    {
        $packet = $this->packet();
        $packet->setUserID("abc");
        return (new Strings((string) $packet->getUserID()))->assertEquals("abc");
    }

    public function getUserID()
    {
        return (new Booleans($this->packet()->getUserID() === null))->assertTrue();
    }

    public function setCallback()
    {
        $packet = $this->packet();
        $packet->setCallback("/next");
        return (new Strings($packet->getCallback() ?? ""))->assertEquals("/next");
    }

    public function getCallback()
    {
        return (new Booleans($this->packet()->getCallback() === null))->assertTrue();
    }
}
