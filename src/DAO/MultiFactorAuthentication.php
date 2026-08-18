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
     * Atomically consumes a successfully verified TOTP counter.
     *
     * Implementations must return false when the counter is less than or equal
     * to the last counter consumed for this user. The comparison and update
     * must happen atomically to prevent concurrent replay.
     * 
     * UPDATE user_mfa SET last_totp_counter = :counter WHERE
     * user_id = :user_id AND (last_totp_counter IS NULL OR last_totp_counter < :counter)
     *
     * @param int|string $userID
     * @param int $counter
     * @return bool Whether the counter was consumed
     */
    public function consumeTotpCounter(int|string $userID, int $counter): bool;
}
