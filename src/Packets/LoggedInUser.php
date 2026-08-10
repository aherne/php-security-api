<?php

namespace Lucinda\WebSecurity\Packets;

/**
 * Holds info about logged in user
 */
final class LoggedInUser extends Packet
{
    private ?string $accessToken = null;

    /**
     * Forces setting user id
     * 
     * @param int|string $userID
     */
    public function __construct(int|string $userID)
    {
        $this->setUserID($userID);
    }

    /**
     * Sets access token to keep authenticated state across requests for RESTful apps
     * 
     * @param string $accessToken
     */
    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Gets access token that keeps authenticated state
     * 
     * @return ?string
     */
    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }
}