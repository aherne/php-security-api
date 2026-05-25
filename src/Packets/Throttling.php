<?php

namespace Lucinda\WebSecurity\Packets;

use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus as MultifactorResultStatus;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus as AuthenticationResultStatus;

/**
 * Holds the outcome of authentication/authorization
 */
final class Throttling extends Packet
{
    private MultifactorResultStatus|AuthenticationResultStatus $status;
    private ?int $timePenalty = null;

    /**
     * Sets up object state.
     *
     * @param MultifactorResultStatus|AuthenticationResultStatus $status
     */
    public function __construct(MultifactorResultStatus|AuthenticationResultStatus $status)
    {
        $this->setStatus($status);
    }

    /**
     * Sets redirection reason.
     *
     * @param MultifactorResultStatus|AuthenticationResultStatus $status
     */
    public function setStatus(MultifactorResultStatus|AuthenticationResultStatus $status): void
    {
        if ($status != MultifactorResultStatus::THROTTLED && $status != AuthenticationResultStatus::LOGIN_THROTTLED) {
            throw new Exception("Invalid status used!");
        }
        $this->status = $status;
    }

    /**
     * Gets redirection reason.
     *
     * @return MultifactorResultStatus|AuthenticationResultStatus
     */
    public function getStatus(): MultifactorResultStatus|AuthenticationResultStatus
    {
        return $this->status;
    }

    /**
     * Sets number of seconds client will be banned from authenticating
     *
     * @param int $timePenalty
     */
    public function setTimePenalty(int $timePenalty): void
    {
        $this->timePenalty = $timePenalty;
    }

    /**
     * Gets number of seconds client will be banned from authenticating
     *
     * @return int|null
     */
    public function getTimePenalty(): ?int
    {
        if (!$this->timePenalty) {
            throw new Exception("Time penalty must be set beforehand!");
        }
        return $this->timePenalty;
    }
}
