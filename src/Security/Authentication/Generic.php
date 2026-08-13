<?php

namespace Lucinda\WebSecurity\Security\Authentication;

use Lucinda\WebSecurity\Packets\GuestUser;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;

/**
 * Encapsulates Generic logic.
 */
class Generic
{
    protected int|string|null $userID;
    protected Request $request;
    protected SecurityPacket|ThrottlingPacket|GuestUser|null $outcome = null;

    /**
     * Gets callback.
     *
     * @param string $route
     * @return string
     */
    protected function getCallback(string $route): string
    {
        return $this->request->getContextPath()."/".$route;
    }

    /**
     * Gets outcome.
     *
     * @return SecurityPacket|ThrottlingPacket|null
     */
    public function getOutcome(): SecurityPacket|ThrottlingPacket|GuestUser|null
    {
        return $this->outcome;
    }
}
