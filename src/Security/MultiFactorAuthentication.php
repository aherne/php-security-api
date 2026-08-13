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
 * Encapsulates MultiFactorAuthentication logic.
 */
final class MultiFactorAuthentication
{
    private MultiFactorPacket|ThrottlingPacket|null $outcome = null;

    /**
     * Sets up object state.
     *
     * @param Configuration $configuration
     * @param Request $request
     * @param ?LoggedInUserInfo $userInfo
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
     * Authenticate by TOTP.
     *
     * @param Configuration $configuration
     * @param Request $request
     * @param int|string $userID
     * @return MultiFactorPacket|ThrottlingPacket|null
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
     * Gets outcome.
     *
     * @return MultiFactorPacket|ThrottlingPacket|null
     */
    public function getOutcome(): MultiFactorPacket|ThrottlingPacket|null
    {
        return $this->outcome;
    }
}
