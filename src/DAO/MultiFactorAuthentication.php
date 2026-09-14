<?php

namespace Lucinda\WebSecurity\DAO;

/**
 * Defines the DAO contract for MFA policy, TOTP enrollment and replay protection
 *
 * Register the implementation class through the 'dao' attribute
 * of security > multi_factor_authentication.
 *
 * @see \Lucinda\WebSecurity\Configuration\MultiFactorAuthentication
 */
interface MultiFactorAuthentication
{
    /**
     * Checks whether application policy requires MFA for this local user
     *
     * This is independent of enrollment: a user who requires MFA but has no enrolled
     * secret is directed to setup.
     *
     * @param int|string $userID Non-empty local user ID
     * @return bool True when MFA must be completed; false when it is not required
     */
    public function isRequired(int|string $userID): bool;
    /**
     * Gets the account label used in the authenticator provisioning URI
     *
     * @param int|string $userID Non-empty local user ID
     * @return string Account label, such as a username or email address
     */
    public function getAccountName(int|string $userID): string;
    /**
     * Gets the user's enrolled TOTP secret
     *
     * @param int|string $userID Non-empty local user ID
     * @return string|null Base32-encoded secret, or null when TOTP is not enrolled
     */
    public function getSecret(int|string $userID): ?string;
    /**
     * Gets the temporary TOTP secret awaiting enrollment confirmation
     *
     * @param int|string $userID Non-empty local user ID
     * @return string|null Base32-encoded setup secret, or null when none has been stored
     */
    public function getSetupSecret(int|string $userID): ?string;
    /**
     * Stores a temporary TOTP secret for a later enrollment attempt
     *
     * Keep this separate from the enrolled secret; storing it must not enable MFA.
     *
     * @param int|string $userID Non-empty local user ID
     * @param string $secret Base32-encoded secret generated for setup
     */
    public function saveSetupSecret(int|string $userID, string $secret): void;
    /**
     * Stores the confirmed setup secret as the user's enrolled TOTP secret
     *
     * Called after a setup code has been verified and its counter consumed.
     * Preserve that consumed counter so the confirmation code cannot be replayed.
     *
     * @param int|string $userID Non-empty local user ID
     * @param string $secret Base32-encoded secret confirmed during setup
     */
    public function enable(int|string $userID, string $secret): void;
    /**
     * Removes the temporary setup secret after successful enrollment
     *
     * The enrolled secret must remain available through getSecret().
     *
     * @param int|string $userID Non-empty local user ID
     */
    public function clearSetupSecret(int|string $userID): void;

    /**
     * Atomically records a successfully verified TOTP counter to prevent replay
     *
     * Return false when the counter is less than or equal to the last counter
     * consumed for this user. The comparison and update must be atomic so concurrent
     * attempts cannot both succeed. Accept the first counter when none is stored.
     * This operation is also called during setup, before enable().
     *
     * Example conditional update:
     * <code>
     * UPDATE user_mfa SET last_totp_counter = :counter WHERE
     * user_id = :user_id AND (last_totp_counter IS NULL OR last_totp_counter < :counter)
     * </code>
     *
     * @param int|string $userID Non-empty local user ID
     * @param int $counter Verified TOTP time-step counter, not the submitted code
     * @return bool True when the counter was recorded; false when it was already consumed or is older
     */
    public function consumeTotpCounter(int|string $userID, int $counter): bool;
}
