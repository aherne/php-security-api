<?php

namespace Lucinda\WebSecurity\Security\MultiFactorAuthentication;

use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\Request;

/**
 * Encapsulates Generic logic.
 */
abstract class Generic
{
    protected Request $request;
    protected int|string $userID;
    protected MultiFactorPacket|ThrottlingPacket|null $outcome = null;

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
     * Compose.
     *
     * @param ResultStatus $status
     * @param string $route
     * @return MultiFactorPacket
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
     * Compose throttling.
     *
     * @param string $route
     * @return ThrottlingPacket
     */
    protected function composeThrottling(string $route): ThrottlingPacket
    {
        $packet = new ThrottlingPacket(ResultStatus::THROTTLED);
        $packet->setUserID($this->userID);
        $packet->setCallback($this->getCallback($route));
        return $packet;
    }

    /**
     * Gets outcome.
     *
     * @return MultiFactorPacket|ThrottlingPacket|null
     */
    public function getOutcome(): MultiFactorPacket|ThrottlingPacket|null
    {
        return $this->outcome;
    }
}
