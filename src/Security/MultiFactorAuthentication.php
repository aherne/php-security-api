<?php

namespace Lucinda\WebSecurity\Security;

use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication as Configuration;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication\Totp as TotpConfiguration;
use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp;

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
     * @param int|string|null $userID
     */
    public function __construct(Configuration $configuration, Request $request, int|string|null $userID)
    {
        if ($userID === null) {
            return;
        }

        $method = $configuration->getMethod();
        if ($method instanceof TotpConfiguration) {
            $this->outcome = $this->authenticateByTotp($configuration, $request, $userID);
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
