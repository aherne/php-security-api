<?php

namespace Lucinda\WebSecurity\Packets;

/**
 * Holds info about logged in user
 */
final class LoggedInUser extends Packet
{
    private string $csrfToken;

    /**
     * Forces setting user id
     * 
     * @param int|string $userID
     * @param string $csrfToken
     */
    public function __construct(int|string $userID, string $csrfToken)
    {
        $this->setUserID($userID);
        $this->csrfToken = $csrfToken;
    }

    public function getCsrfToken(): string
    {
        return $this->csrfToken;
    }
}