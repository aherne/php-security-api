<?php

namespace Lucinda\WebSecurity\Security\Authentication;

use Lucinda\WebSecurity\Packets\GuestUser;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;

/**
 * Shares request context, callback construction, and outcome storage for authentication handlers
 *
 * Concrete handlers execute their workflow and assign the outcome. This
 * base class neither processes a request nor performs a redirect by itself.
 *
 * @internal
 * @see \Lucinda\WebSecurity\Security\Authentication
 */
class Generic
{
    protected int|string|null $userID;
    protected Request $request;
    protected SecurityPacket|ThrottlingPacket|GuestUser|null $outcome = null;

    /**
     * Builds a redirect path relative to the request's application context
     *
     * @param string $route Configured route relative to the application context
     * @return string Context-prefixed redirect path; no redirect is performed
     */
    protected function getCallback(string $route): string
    {
        return $this->request->getContextPath()."/".$route;
    }

    /**
     * Gets the outcome computed by the concrete authentication handler
     *
     * @return SecurityPacket|ThrottlingPacket|GuestUser|null Computed outcome, or null when the handler produced none
     */
    public function getOutcome(): SecurityPacket|ThrottlingPacket|GuestUser|null
    {
        return $this->outcome;
    }
}
