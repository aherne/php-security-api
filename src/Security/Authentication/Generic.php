<?php

namespace Lucinda\WebSecurity\Security\Authentication;

use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;

class Generic
{
    protected int|string|null $userID;
    protected Request $request;
    protected SecurityPacket|ThrottlingPacket|null $outcome = null;

    protected function getCallback(string $route): string
    {
        return $this->request->getContextPath()."/".$route;
    }

    public function getOutcome(): SecurityPacket|ThrottlingPacket|null
    {
        return $this->outcome;
    }
}
