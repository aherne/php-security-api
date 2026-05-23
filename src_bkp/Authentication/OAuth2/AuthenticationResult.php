<?php

namespace Lucinda\WebSecurity\Authentication\OAuth2;

/**
 * Encapsulates authentication response via oauth2 driver
 */
class AuthenticationResult extends \Lucinda\WebSecurity\Authentication\Result
{
    private string $token;

    /**
     * Sets access token.
     *
     * @param string $token
     */
    public function setAccessToken(string $token): void
    {
        $this->token = $token;
    }

    /**
     * Gets access token
     *
     * @return string
     */
    public function getAccessToken(): string
    {
        return $this->token;
    }
}
