<?php

namespace Lucinda\WebSecurity\Packets;

/**
 * Represents a fully authenticated user and supplies their CSRF token
 *
 * Carries the local user ID after all required authentication stages
 * have completed. This outcome does not imply permission to access
 * every resource.
 *
 * @see \Lucinda\WebSecurity\Wrapper::getOutcome()
 */
final class LoggedInUser extends Packet
{
    private string $csrfToken;

    /**
     * Creates the fully authenticated user outcome
     *
     * @param int|string $userID Non-empty local ID of the authenticated user
     * @param string $csrfToken CSRF token generated for the authenticated user
     */
    public function __construct(int|string $userID, string $csrfToken)
    {
        $this->setUserID($userID);
        $this->csrfToken = $csrfToken;
    }

    /**
     * Gets the CSRF token for protected requests by the authenticated user
     *
     * @return string CSRF token associated with the authenticated user
     */
    public function getCsrfToken(): string
    {
        return $this->csrfToken;
    }
}