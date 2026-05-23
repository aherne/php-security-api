<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Authentication\ResultStatus as AuthenticationResultStatus;
use Lucinda\WebSecurity\Authorization\ResultStatus as AuthorizationResultStatus;
use Lucinda\WebSecurity\Authentication\MultiFactor\ResultStatus as MultifactorResultStatus;
use Lucinda\WebSecurity\PersistenceDrivers\Token\PersistenceDriver as TokenPersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;

/**
 * Holds information about authentication/authorization outcomes incompatible with continuing execution
 * (requiring a redirection).
 */
class SecurityPacket extends \Exception
{
    private string $callback;
    private string $status;
    private ?string $accessToken;
    private ?int $timePenalty;

    /**
     * Sets path to redirect to.
     *
     * @param string $callback
     */
    public function setCallback(string $callback): void
    {
        $this->callback = $callback;
    }

    /**
     * Gets path to redirect to.
     *
     * @return string
     */
    public function getCallback(): string
    {
        return $this->callback;
    }

    /**
     * Sets redirection reason.
     *
     * @param AuthenticationResultStatus|AuthorizationResultStatus|MultifactorResultStatus $status
     */
    public function setStatus(AuthenticationResultStatus|AuthorizationResultStatus|MultifactorResultStatus $status): void
    {
        $this->status = match ($status) {
            AuthenticationResultStatus::LOGIN_OK => "login_ok",
            AuthenticationResultStatus::LOGIN_FAILED => "login_failed",
            AuthenticationResultStatus::LOGIN_THROTTLED => "login_throttled",
            AuthenticationResultStatus::LOGOUT_OK => "logout_ok",
            AuthenticationResultStatus::LOGOUT_FAILED => "logout_failed",
            AuthenticationResultStatus::DEFERRED => "redirect",
            AuthorizationResultStatus::UNAUTHORIZED => "unauthorized",
            AuthorizationResultStatus::FORBIDDEN => "forbidden",
            AuthorizationResultStatus::NOT_FOUND => "not_found",
            MultifactorResultStatus::SETUP_REQUIRED => "mfa_setup",
            MultifactorResultStatus::REQUIRED => "mfa_required",
            MultifactorResultStatus::THROTTLED => "mfa_throttled",
            default => "",
        };;
    }

    /**
     * Gets redirection reason.
     *
     * @return string
     */
    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * Sets access token (useful for stateless applications).
     *
     * @param int|string|null     $userID             Authenticated user id.
     * @param PersistenceDriver[] $persistenceDrivers List of persistence drivers registered.
     */
    public function setAccessToken(int|string|null $userID, array $persistenceDrivers): void
    {
        $token = "";
        if ($userID) {
            foreach ($persistenceDrivers as $persistenceDriver) {
                if ($persistenceDriver instanceof TokenPersistenceDriver) {
                    $token = $persistenceDriver->getAccessToken();
                }
            }
        }
        $this->accessToken = $token;
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

    /**
     * Sets number of seconds client will be banned from authenticating
     *
     * @param int $timePenalty
     */
    public function setTimePenalty(int $timePenalty): void
    {
        $this->timePenalty = $timePenalty;
    }

    /**
     * Gets number of seconds client will be banned from authenticating
     *
     * @return int|null
     */
    public function getTimePenalty(): ?int
    {
        return $this->timePenalty;
    }
}
