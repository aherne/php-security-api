<?php

namespace Lucinda\WebSecurity\Security;

use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication as Configuration;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication\Totp as TotpConfiguration;
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
        if ($userInfo === null || !$this->isMfaDue($configuration, $userInfo)) {
            return; // not logged in or already passed MFA
        }

        $method = $configuration->getMethod();
        if ($method instanceof TotpConfiguration) {
            $this->outcome = $this->authenticateByTotp($configuration, $request, $userInfo->getUserID());
            if ($this->outcome instanceof MultiFactorPacket && $this->outcome->getStatus() == MultifactorResultStatus::SUCCEEDED) {
                $this->outcome->setValidUntil(time()+$configuration->getExpiration());
            }
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

    private function isMfaDue(Configuration $configuration, LoggedInUserInfo $userInfo): bool {
        if ($userInfo->getAuthenticatedStage() === AuthenticationStage::PENDING_MFA) {
            return true;
        }

        $validUntil = $userInfo->getMfaValidUntil();

        return $validUntil === null || time() >= $validUntil;
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
