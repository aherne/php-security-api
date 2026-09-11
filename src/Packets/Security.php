<?php

namespace Lucinda\WebSecurity\Packets;

use Lucinda\WebSecurity\Security\Authentication\ResultStatus as AuthenticationResultStatus;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus as AuthorizationResultStatus;
use Lucinda\WebSecurity\Security\FailureReason;

/**
 * Holds the outcome of authentication/authorization
 */
final class Security extends Packet
{
    private AuthenticationResultStatus|AuthorizationResultStatus|null $status = null;

    /**
     * Sets up object state.
     *
     * @param AuthenticationResultStatus|AuthorizationResultStatus $status
     * @param ?string $callback
     * @param ?FailureReason $failureReason
     */
    public function __construct(
        AuthenticationResultStatus|AuthorizationResultStatus $status,
        ?string $callback = null,
        ?FailureReason $failureReason = null
        )
    {
        $this->setStatus($status);
        $this->setCallback($callback);
        $this->setFailureReason($failureReason);
    }

    /**
     * Sets redirection reason.
     *
     * @param AuthenticationResultStatus|AuthorizationResultStatus $status
     */
    public function setStatus(AuthenticationResultStatus|AuthorizationResultStatus $status): void
    {
        $this->status = $status;
    }

    /**
     * Gets redirection reason.
     *
     * @return AuthenticationResultStatus|AuthorizationResultStatus|null
     */
    public function getStatus(): AuthenticationResultStatus|AuthorizationResultStatus|null
    {
        return $this->status;
    }
}