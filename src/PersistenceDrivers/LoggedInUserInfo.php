<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\WebSecurity\Security\Exception;

/**
 * Carries authentication state stored by persistence drivers
 *
 * Includes the local user ID, authentication stage, remember-me preference,
 * and optional stage deadline. A user ID alone does not establish completed
 * authentication: the state may still be awaiting MFA.
 *
 * @see PersistenceDriver
 * @see AuthenticationStage
 */
final class LoggedInUserInfo
{
    private int|string $userID;
    private AuthenticationStage $stage;
    private ?int $stageValidUntil = null;
    private bool $rememberRequested = false;

    /**
     * Creates the authentication state to persist
     *
     * @param int|string $userID Non-empty local user ID; zero and empty strings are not supported
     * @param AuthenticationStage $stage Current authentication stage
     * @param bool $rememberRequested Whether remember-me persistence was requested
     * @param int|null $stageValidUntil Stage deadline as a Unix timestamp in seconds, or null when not recorded
     * @throws Exception If the user ID is empty
     */
    public function __construct(
        int|string $userID,
        AuthenticationStage $stage,
        bool $rememberRequested = false,
        ?int $stageValidUntil = null
    ) {
        if (empty($userID)) {
            throw new Exception("User ID cannot be empty!");
        }
        $this->userID = $userID;
        $this->stage = $stage;
        $this->rememberRequested = $rememberRequested;
        $this->stageValidUntil = $stageValidUntil;
    }

    /**
     * Gets the local user ID associated with the authentication state
     *
     * @return int|string Non-empty local user ID
     */
    public function getUserID(): int|string
    {
        return $this->userID;
    }

    /**
     * Gets the current authentication stage
     *
     * @return AuthenticationStage Whether MFA is pending or authentication is complete
     */
    public function getAuthenticatedStage(): AuthenticationStage
    {
        return $this->stage;
    }

    /**
     * Gets the deadline associated with the authentication stage
     *
     * For PENDING_MFA, the deadline bounds the time allowed to complete MFA;
     * a missing deadline is treated as expired. For AUTHENTICATED, it marks
     * the end of verified MFA freshness. A missing or expired deadline causes
     * MFA policy to be evaluated again when MFA is configured.
     *
     * @return int|null Stage deadline as a Unix timestamp in seconds, or null when not recorded
     */
    public function getStageValidUntil(): ?int
    {
        return $this->stageValidUntil;
    }

    /**
     * Gets whether remember-me persistence was requested
     *
     * The preference does not indicate that a remember-me cookie was issued.
     *
     * @return bool True when remember-me persistence was requested
     */
    public function rememberRequested(): bool
    {
        return $this->rememberRequested;
    }
}