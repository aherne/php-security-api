<?php

namespace Lucinda\WebSecurity\Packets;

use Lucinda\WebSecurity\Security\Authentication\ResultStatus as AuthenticationResultStatus;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus as AuthorizationResultStatus;
use Lucinda\WebSecurity\Security\FailureReason;

/**
 * Carries the result of an authentication or authorization operation
 *
 * The status describes the workflow result, while an optional failure
 * reason supplies further detail. A redirect destination may be provided
 * for the caller to handle.
 *
 * @see \Lucinda\WebSecurity\Security\Authentication\ResultStatus
 * @see \Lucinda\WebSecurity\Security\Authorization\ResultStatus
 * @see \Lucinda\WebSecurity\Security\FailureReason
 */
final class Security extends Packet
{
    private AuthenticationResultStatus|AuthorizationResultStatus|null $status = null;

    /**
     * Creates an authentication or authorization outcome
     *
     * @param AuthenticationResultStatus|AuthorizationResultStatus $status Workflow result
     * @param string|null $callback Redirect path or URL, or null when no redirect is specified
     * @param FailureReason|null $failureReason Failure detail, or null when none is attached
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
     * Sets the authentication or authorization result
     *
     * @param AuthenticationResultStatus|AuthorizationResultStatus $status Workflow result
     */
    public function setStatus(AuthenticationResultStatus|AuthorizationResultStatus $status): void
    {
        $this->status = $status;
    }

    /**
     * Gets the authentication or authorization result
     *
     * @return AuthenticationResultStatus|AuthorizationResultStatus|null Assigned workflow result
     */
    public function getStatus(): AuthenticationResultStatus|AuthorizationResultStatus|null
    {
        return $this->status;
    }
}