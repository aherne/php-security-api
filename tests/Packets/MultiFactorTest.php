<?php
namespace Test\Lucinda\WebSecurity\Packets;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Packets\MultiFactor;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus;

class MultiFactorTest
{
    private function packet(): MultiFactor
    {
        return new MultiFactor();
    }

    public function setStatus()
    {
        $packet = $this->packet();
        $packet->setStatus(ResultStatus::SUCCEEDED);
        return (new Booleans($packet->getStatus() === ResultStatus::SUCCEEDED))->assertTrue();
    }

    public function getStatus()
    {
        return (new Booleans($this->packet()->getStatus() === null))->assertTrue();
    }

    public function setUserID()
    {
        $packet = $this->packet();
        $packet->setUserID("u1");
        return (new Strings((string) $packet->getUserID()))->assertEquals("u1");
    }

    public function getUserID()
    {
        return (new Booleans($this->packet()->getUserID() === null))->assertTrue();
    }

    public function setCallback()
    {
        $packet = $this->packet();
        $packet->setCallback("mfa");
        return (new Strings($packet->getCallback() ?? ""))->assertEquals("mfa");
    }

    public function getCallback()
    {
        return (new Booleans($this->packet()->getCallback() === null))->assertTrue();
    }

    public function setSecret()
    {
        $packet = $this->packet();
        $packet->setSecret("secret");
        return (new Strings($packet->getSecret() ?? ""))->assertEquals("secret");
    }

    public function getSecret()
    {
        return (new Booleans($this->packet()->getSecret() === null))->assertTrue();
    }

    public function setProvisioningURI()
    {
        $packet = $this->packet();
        $packet->setProvisioningURI("otpauth://x");
        return (new Strings($packet->getProvisioningURI() ?? ""))->assertEquals("otpauth://x");
    }

    public function getProvisioningURI()
    {
        return (new Booleans($this->packet()->getProvisioningURI() === null))->assertTrue();
    }
    public function setValidUntil()
    {
    }
        

    public function getValidUntil()
    {
    }
        

    public function setAccessToken()
    {
    }
        

    public function getAccessToken()
    {
    }
        

}
