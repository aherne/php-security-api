<?php

namespace Lucinda\WebSecurity\Security\MultiFactorAuthentication;

use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\Request;

abstract class Generic
{
    protected Request $request;
    protected int|string $userID;
    protected MultiFactorPacket|ThrottlingPacket|null $outcome = null;

    protected function getCallback(string $route): string
    {
        return $this->request->getContextPath()."/".$route;
    }

    protected function compose(ResultStatus $status, string $route): MultiFactorPacket
    {
        $packet = new MultiFactorPacket();
        $packet->setUserID($this->userID);
        $packet->setStatus($status);
        $packet->setCallback($this->getCallback($route));
        return $packet;
    }

    protected function composeThrottling(string $route): ThrottlingPacket
    {
        $packet = new ThrottlingPacket(ResultStatus::THROTTLED);
        $packet->setUserID($this->userID);
        $packet->setCallback($this->getCallback($route));
        return $packet;
    }

    public function getOutcome(): MultiFactorPacket|ThrottlingPacket|null
    {
        return $this->outcome;
    }
}
