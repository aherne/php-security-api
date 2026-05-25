<?php

namespace Lucinda\WebSecurity\DAO;

/**
 * Defines multi-factor authentication DAO contract.
 */
interface MultiFactorAuthentication
{
    /**
     * Checks whether multi-factor authentication is required.
     *
     * @param int|string $userID
     * @return bool
     */
    public function isRequired(int|string $userID): bool;
    /**
     * Gets account name.
     *
     * @param int|string $userID
     * @return string
     */
    public function getAccountName(int|string $userID): string;
    /**
     * Gets secret.
     *
     * @param int|string $userID
     * @return ?string
     */
    public function getSecret(int|string $userID): ?string;
    /**
     * Gets setup secret.
     *
     * @param int|string $userID
     * @return ?string
     */
    public function getSetupSecret(int|string $userID): ?string;
    /**
     * Saves setup secret.
     *
     * @param int|string $userID
     * @param string $secret
     */
    public function saveSetupSecret(int|string $userID, string $secret): void;
    /**
     * Enables multi-factor authentication.
     *
     * @param int|string $userID
     * @param string $secret
     */
    public function enable(int|string $userID, string $secret): void;
    /**
     * Clears setup secret.
     *
     * @param int|string $userID
     */
    public function clearSetupSecret(int|string $userID): void;
    /**
     * Records a failed multi-factor attempt.
     *
     * @param int|string $userID
     */
    public function penalize(int|string $userID): void;
    /**
     * Checks whether multi-factor authentication is throttled.
     *
     * @param int|string $userID
     * @return bool
     */
    public function isThrottled(int|string $userID): bool;
}
