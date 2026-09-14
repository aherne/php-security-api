<?php

namespace Lucinda\WebSecurity\Packets;

use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus as MultifactorResultStatus;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus as AuthenticationResultStatus;

/**
 * Indicates that login or multi-factor authentication attempts are throttled
 *
 * Accepts only AuthenticationResultStatus::LOGIN_THROTTLED or
 * MultifactorResultStatus::THROTTLED. An optional inherited redirect
 * destination lets the caller route the user to the appropriate response.
 *
 * @see \Lucinda\WebSecurity\Security\Authentication\ResultStatus
 * @see \Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus
 */
final class Throttling extends Packet
{
    private MultifactorResultStatus|AuthenticationResultStatus $status;

    /**
     * Creates an outcome for throttled login or MFA attempts
     *
     * @param MultifactorResultStatus|AuthenticationResultStatus $status THROTTLED or LOGIN_THROTTLED
     * @throws Exception If the supplied status does not represent throttling
     */
    public function __construct(MultifactorResultStatus|AuthenticationResultStatus $status)
    {
        $this->setStatus($status);
    }

    /**
     * Sets the throttling result
     *
     * @param MultifactorResultStatus|AuthenticationResultStatus $status THROTTLED or LOGIN_THROTTLED
     * @throws Exception If the supplied status does not represent throttling
     */
    public function setStatus(MultifactorResultStatus|AuthenticationResultStatus $status): void
    {
        if ($status != MultifactorResultStatus::THROTTLED && $status != AuthenticationResultStatus::LOGIN_THROTTLED) {
            throw new Exception("Invalid status used!");
        }
        $this->status = $status;
    }

    /**
     * Gets the throttling result
     *
     * @return MultifactorResultStatus|AuthenticationResultStatus THROTTLED or LOGIN_THROTTLED
     */
    public function getStatus(): MultifactorResultStatus|AuthenticationResultStatus
    {
        return $this->status;
    }
}
