<?php

namespace Lucinda\WebSecurity\Packets;

use Lucinda\WebSecurity\Security\FailureReason;

/**
 * Holds the outcome of authentication/authorization
 */
abstract class Packet
{
    private ?string $callback = null;
    private int|string|null $userID = null;
    private ?string $accessToken = null;
    private ?FailureReason $failureReason = null;

    /**
     * Sets user ID
     * 
     * @param int|string $userID
     */
    public function setUserID(int|string $userID): void
    {
        $this->userID = $userID;
    }

    /**
     * Gets user ID
     * 
     * @return int|string|null
     */
    public function getUserID(): int|string|null
    {
        return $this->userID;
    }

    /**
     * Sets path to redirect to.
     *
     * @param ?string $callback
     */
    public function setCallback(?string $callback): void
    {
        $this->callback = $callback;
    }

    /**
     * Gets path to redirect to.
     *
     * @return ?string
     */
    public function getCallback(): ?string
    {
        return $this->callback;
    }

    public function setFailureReason(?FailureReason $failureReason): void
    {
        $this->failureReason = $failureReason;
    }

    public function getFailureReason(): ?FailureReason
    {
        return $this->failureReason;
    }

    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }
}
