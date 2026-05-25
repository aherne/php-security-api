<?php

namespace Lucinda\WebSecurity\Packets;

use Lucinda\WebSecurity\Security\Authentication\ResultStatus as AuthenticationResultStatus;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus as AuthorizationResultStatus;

/**
 * Holds the outcome of authentication/authorization
 */
final class Security extends Packet
{
    private AuthenticationResultStatus|AuthorizationResultStatus|null $status = null;
    private ?string $accessToken = null;

    /**
     * Sets up object state.
     *
     * @param AuthenticationResultStatus|AuthorizationResultStatus $status
     * @param ?string $callback
     */
    public function __construct(AuthenticationResultStatus|AuthorizationResultStatus $status, ?string $callback = null)
    {
        $this->setStatus($status);
        $this->setCallback($callback);
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

    /**
     * Sets access token (useful for stateless applications).
     *
     * @param string $accessToken
     */
    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Gets access token. In order to stay authenticated, each request will have to include this as a header.
     *
     * @return string|null
     */
    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }
}