<?php

namespace Lucinda\WebSecurity\Security;

use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication as Configuration;
use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus as MultifactorResultStatus;

/**
 * Evaluates authentication-stage deadlines and executes MFA when needed
 *
 * Construction rejects expired pending-MFA state, skips authenticated state
 * whose MFA validity is still fresh, and otherwise delegates to TOTP handling.
 * Successful verification receives a new MFA-validity deadline. The computed
 * packet is available through getOutcome(); persistence is handled by the
 * enclosing wrapper.
 *
 * @see \Lucinda\WebSecurity\Configuration\MultiFactorAuthentication
 * @see \Lucinda\WebSecurity\Wrapper\MultiFactorAuthentication
 * @see \Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo
 */
final class MultiFactorAuthentication
{
    private MultiFactorPacket|ThrottlingPacket|null $outcome = null;

    /**
     * Constructs and executes MFA evaluation for the supplied authentication state
     *
     * Delegated processing may modify enrollment data, consume a verified
     * counter, or record a failed attempt.
     *
     * @param Configuration $configuration Parsed MFA settings and configured DAO classes
     * @param Request $request Current request to evaluate
     * @param LoggedInUserInfo|null $userInfo Persisted authentication state, or null when no identity is available
     * @throws \Throwable If a DAO, throttler, or TOTP operation fails
     */
    public function __construct(Configuration $configuration, Request $request, ?LoggedInUserInfo $userInfo = null)
    {
        if ($userInfo === null) {
            // not logged in => no MFA
            return; 
        }
        
        $validUntil = $userInfo->getStageValidUntil();
        $now = time();

        if ($userInfo->getAuthenticatedStage() === AuthenticationStage::PENDING_MFA) {
            if ($validUntil === null || $now >= $validUntil) {
                // PENDING_MFA and deadline expired
                $outcome = new MultiFactorPacket();
                $outcome->setUserID($userInfo->getUserID());
                $outcome->setStatus(MultifactorResultStatus::EXPIRED);
                $this->outcome = $outcome; // PENDING_MFA and deadline expired
                return;
            }

            // Pending and still valid: execute MFA.
        } elseif ($validUntil !== null && $now < $validUntil) {
            // Authenticated and MFA is still fresh.
            return;
        }

        // Authenticated with null/expired validity: evaluate MFA.
        $this->outcome = $this->authenticateByTotp($configuration, $request, $userInfo->getUserID());
        if ($this->outcome instanceof MultiFactorPacket && $this->outcome->getStatus() == MultifactorResultStatus::SUCCEEDED) {
            $this->outcome->setValidUntil(time()+$configuration->getExpiration());
        }
    }

    /**
     * Delegates enrollment or challenge handling to the TOTP implementation
     *
     * @param Configuration $configuration Parsed MFA and TOTP settings
     * @param Request $request Current request to evaluate
     * @param int|string $userID Non-empty local ID whose MFA requirements are evaluated
     * @return MultiFactorPacket|ThrottlingPacket|null Computed TOTP outcome, or null when none is produced
     * @throws \Throwable If a DAO, throttler, or TOTP operation fails
     */
    private function authenticateByTotp(
        Configuration $configuration,
        Request $request,
        int|string $userID
    ): MultiFactorPacket|ThrottlingPacket|null
    {
        $authenticator = new Totp($configuration, $request, $userID);
        return $authenticator->getOutcome();
    }

    /**
     * Gets the MFA outcome computed during construction
     *
     * @return MultiFactorPacket|ThrottlingPacket|null Computed outcome, or null for absent user state or still-fresh authentication
     */
    public function getOutcome(): MultiFactorPacket|ThrottlingPacket|null
    {
        return $this->outcome;
    }
}
