<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\Token;

/**
 * Encapsulates a driver that persists unique user identifier into a crypted self-regenerating token that
 * must be sent by clients via Authorization header of bearer type.
 */
abstract class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
{
    protected ?string $accessToken = null;

    /**
     * Sets access token value based on contents of HTTP authorization header of "bearer" type
     *
     * @param string $accessToken
     */
    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Gets access token value.
     *
     * @return ?string
     */
    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }
}
