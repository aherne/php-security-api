<?php

namespace Lucinda\WebSecurity\Packets;

use Lucinda\WebSecurity\Security\FailureReason;

/**
 * Defines the shared data carried by security workflow outcomes
 *
 * Concrete packet types describe the outcome for the caller to handle.
 * Carries an optional local user ID, redirect destination, access token,
 * and detailed failure reason. A user ID alone does not indicate
 * completed authentication.
 *
 * @see \Lucinda\WebSecurity\Wrapper::getOutcome()
 */
abstract class Packet
{
    private ?string $callback = null;
    private int|string|null $userID = null;
    private ?string $accessToken = null;
    private ?FailureReason $failureReason = null;

    /**
     * Sets the local user ID associated with this outcome
     *
     * Assigning an ID does not mark authentication as complete.
     *
     * @param int|string $userID Non-empty local user ID
     */
    public function setUserID(int|string $userID): void
    {
        $this->userID = $userID;
    }

    /**
     * Gets the local user ID associated with this outcome
     *
     * Identification does not imply that all authentication stages succeeded.
     *
     * @return int|string|null Local user ID, or null when none was assigned
     */
    public function getUserID(): int|string|null
    {
        return $this->userID;
    }

    /**
     * Sets the redirect destination for the caller to handle
     *
     * Stores the destination without performing a redirect.
     *
     * @param string|null $callback Redirect path or URL, or null to remove the destination
     */
    public function setCallback(?string $callback): void
    {
        $this->callback = $callback;
    }

    /**
     * Gets the redirect destination for the caller to handle
     *
     * Reading the destination does not perform a redirect.
     *
     * @return string|null Redirect path or URL, or null when none is specified
     */
    public function getCallback(): ?string
    {
        return $this->callback;
    }

    /**
     * Sets the detailed reason associated with a failed operation
     *
     * @param FailureReason|null $failureReason Failure detail, or null to remove it
     */
    public function setFailureReason(?FailureReason $failureReason): void
    {
        $this->failureReason = $failureReason;
    }

    /**
     * Gets the detailed reason associated with a failed operation
     *
     * The absence of a reason does not imply a successful outcome.
     *
     * @return FailureReason|null Failure detail, or null when none is attached
     */
    public function getFailureReason(): ?FailureReason
    {
        return $this->failureReason;
    }

    /**
     * Attaches the library authentication bearer token to this outcome
     *
     * This is the persistence token, not an OAuth2 provider access token.
     * Treat the value as a credential and exclude it from logs.
     *
     * @param string $accessToken Authentication bearer token to return to the client
     */
    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Gets the library authentication bearer token attached to this outcome
     *
     * Treat the value as a credential and exclude it from logs.
     *
     * @return string|null Authentication bearer token, or null when none is attached
     */
    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }
}
