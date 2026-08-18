<?php

namespace Lucinda\WebSecurity\Detectors;

use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\EncryptionException;
use Lucinda\WebSecurity\Configuration\Csrf as Configuration;

/**
 * Binds SynchronizerToken @ SECURITY-API with settings from configuration.xml @ SERVLETS-API  then sets up an object
 * based on which one can perform CSRF checks later on in application's lifecycle.
 */
final class CsrfToken
{
    public const DEFAULT_EXPIRATION = 10*60;

    private int $expiration;
    private SynchronizerToken $token;

    /**
     * Creates an object
     *
     * @param  Configuration $configuration       Contents of security.csrf @ configuration.xml
     * @param  string            $ipAddress Client ip address resolved from headers
     */
    public function __construct(Configuration $configuration, string $ipAddress)
    {
        // sets secret
        $secret = $configuration->getSecret();

        // sets token
        $this->token = new SynchronizerToken($ipAddress, $secret);

        // sets expiration
        $this->expiration = $configuration->getExpirationTime();
    }

    /**
     * Encodes a token based on unique user identifier
     *
     * @param  int|string|null $userID Unique user identifier (usually an int)
     * @return string Value of synchronizer token.
     * @throws EncryptionException If encryption of token fails.
     */
    public function generate(int|string|null $userID): string
    {
        return $this->token->encode($userID, $this->expiration);
    }

    /**
     * Checks if a token is valid for specific uuid.
     *
     * @param  string          $token  Value of synchronizer token
     * @param  int|string|null $userID Unique user identifier (usually an int)
     * @return boolean
     */
    public function isValid(string $token, int|string|null $userID): bool
    {
        try {
            return $this->token->decode($token) === $userID;
        } catch (\Exception) {
            return false;
        }
    }
}
