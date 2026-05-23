<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\EncryptionException;
use Lucinda\WebSecurity\Token\Exception as TokenException;
use Lucinda\WebSecurity\Token\RegenerationException;

/**
 * Binds SynchronizerToken @ SECURITY-API with settings from configuration.xml @ SERVLETS-API  then sets up an object
 * based on which one can perform CSRF checks later on in application's lifecycle.
 */
class CsrfTokenDetector
{
    public const DEFAULT_EXPIRATION = 10*60;

    private int $expiration;
    private SynchronizerToken $token;

    /**
     * Creates an object
     *
     * @param  \SimpleXMLElement $xml       Contents of security.csrf @ configuration.xml
     * @param  string            $ipAddress Client ip address resolved from headers
     * @throws ConfigurationException If XML is improperly configured.
     */
    public function __construct(\SimpleXMLElement $xml, string $ipAddress)
    {
        $xml = $xml->csrf;
        if (empty($xml)) {
            throw new ConfigurationException("Tag 'csrf' child of 'security' tag is empty or missing");
        }

        // sets secret
        $secret = (string) $xml["secret"];
        if (!$secret) {
            throw new ConfigurationException("Attribute 'secret' is mandatory for 'csrf' tag");
        }

        // sets token
        $this->token = new SynchronizerToken($ipAddress, $secret);

        // sets expiration
        $expiration = (string) $xml["expiration"];
        if (!$expiration) {
            $expiration = self::DEFAULT_EXPIRATION;
        }
        $this->expiration = $expiration;
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
            $tokenUserID = $this->token->decode($token);
            if ($tokenUserID == $userID) {
                return true;
            } else {
                return false;
            }
        } catch (\Exception) {
            return false;
        }
    }
}
