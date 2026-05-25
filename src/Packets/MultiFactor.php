<?php

namespace Lucinda\WebSecurity\Packets;

use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus as MultifactorResultStatus;

/**
 * Holds the outcome of authentication/authorization
 */
final class MultiFactor extends Packet
{
    private MultifactorResultStatus|null $status = null;
    private ?string $secret = null;
    private ?string $provisioningURI = null;

    /**
     * Sets redirection reason.
     *
     * @param MultifactorResultStatus $status
     */
    public function setStatus(MultifactorResultStatus $status): void
    {
        $this->status = $status;
    }

    /**
     * Gets redirection reason.
     *
     * @return MultifactorResultStatus|null
     */
    public function getStatus(): MultifactorResultStatus|null
    {
        return $this->status;
    }

    /**
     * Sets secret.
     *
     * @param string $secret
     */
    public function setSecret(string $secret): void
    {
        $this->secret = $secret;
    }

    /**
     * Gets secret.
     *
     * @return ?string
     */
    public function getSecret(): ?string
    {
        return $this->secret;
    }

    /**
     * Sets provisioning URI.
     *
     * @param string $provisioningURI
     */
    public function setProvisioningURI(string $provisioningURI): void
    {
        $this->provisioningURI = $provisioningURI;
    }

    /**
     * Gets provisioning URI.
     *
     * @return ?string
     */
    public function getProvisioningURI(): ?string
    {
        return $this->provisioningURI;
    }
}
