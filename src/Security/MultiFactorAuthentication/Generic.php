<?php

namespace Lucinda\WebSecurity\Security\MultiFactorAuthentication;

use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\Request;

/**
 * Shares callback construction and packet composition for MFA implementations
 *
 * Concrete implementations supply the request, local user ID, and computed
 * outcome. Packet composition does not perform redirects or persist login state.
 *
 * @internal
 * @see \Lucinda\WebSecurity\Packets\MultiFactor
 * @see \Lucinda\WebSecurity\Packets\Throttling
 */
abstract class Generic
{
    protected Request $request;
    protected int|string $userID;
    protected MultiFactorPacket|ThrottlingPacket|null $outcome = null;

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
     * Composes an MFA outcome with the current user ID and callback
     *
     * @param ResultStatus $status MFA workflow decision
     * @param string $route Configured destination relative to the application context
     * @return MultiFactorPacket MFA packet containing the status, user ID, and context-prefixed callback
     */
    protected function compose(ResultStatus $status, string $route): MultiFactorPacket
    {
        $packet = new MultiFactorPacket();
        $packet->setUserID($this->userID);
        $packet->setStatus($status);
        $packet->setCallback($this->getCallback($route));
        return $packet;
    }

    /**
     * Composes a throttling outcome for the current MFA user
     *
     * @param string $route Configured throttling route relative to the application context
     * @return ThrottlingPacket THROTTLED packet containing the user ID and context-prefixed callback
     */
    protected function composeThrottling(string $route): ThrottlingPacket
    {
        $packet = new ThrottlingPacket(ResultStatus::THROTTLED);
        $packet->setUserID($this->userID);
        $packet->setCallback($this->getCallback($route));
        return $packet;
    }

    /**
     * Gets the outcome computed by the concrete MFA implementation
     *
     * @return MultiFactorPacket|ThrottlingPacket|null Computed outcome, or null when none was assigned
     */
    public function getOutcome(): MultiFactorPacket|ThrottlingPacket|null
    {
        return $this->outcome;
    }
}
