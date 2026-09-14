<?php

namespace Lucinda\WebSecurity\Packets;

use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus as MultifactorResultStatus;

/**
 * Carries a multi-factor authentication result and any associated data
 *
 * The status determines the next step in the MFA workflow. TOTP setup
 * outcomes may include an enrollment secret and provisioning URI; these
 * are sensitive credentials and must be excluded from logs. Successful
 * verification may include its validity deadline.
 *
 * @see \Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus
 */
final class MultiFactor extends Packet
{
    private MultifactorResultStatus|null $status = null;
    private ?string $secret = null;
    private ?string $provisioningURI = null;
    private ?int $validUntil = null;

    /**
     * Sets the multi-factor authentication result
     *
     * @param MultifactorResultStatus $status MFA workflow result
     */
    public function setStatus(MultifactorResultStatus $status): void
    {
        $this->status = $status;
    }

    /**
     * Gets the multi-factor authentication result
     *
     * @return MultifactorResultStatus|null MFA workflow result, or null when none was assigned
     */
    public function getStatus(): MultifactorResultStatus|null
    {
        return $this->status;
    }

    /**
     * Attaches the TOTP enrollment secret for authenticator setup
     *
     * The secret is sensitive credential material and must not be logged.
     *
     * @param string $secret Base32-encoded TOTP enrollment secret
     */
    public function setSecret(string $secret): void
    {
        $this->secret = $secret;
    }

    /**
     * Gets the TOTP enrollment secret for authenticator setup
     *
     * The secret is sensitive credential material and must not be logged.
     *
     * @return string|null Base32-encoded enrollment secret, or null when none is attached
     */
    public function getSecret(): ?string
    {
        return $this->secret;
    }

    /**
     * Attaches the TOTP provisioning URI for authenticator enrollment
     *
     * The URI includes the enrollment secret and must not be logged.
     *
     * @param string $provisioningURI otpauth URI suitable for encoding as an enrollment QR code
     */
    public function setProvisioningURI(string $provisioningURI): void
    {
        $this->provisioningURI = $provisioningURI;
    }

    /**
     * Gets the TOTP provisioning URI for authenticator enrollment
     *
     * The URI includes the enrollment secret and must not be logged.
     *
     * @return string|null otpauth enrollment URI, or null when none is attached
     */
    public function getProvisioningURI(): ?string
    {
        return $this->provisioningURI;
    }

    /**
     * Sets the validity deadline for successful MFA verification
     *
     * This is not the pending challenge deadline or the expiry of a TOTP code.
     *
     * @param int $validUntil Unix timestamp in seconds at which the successful verification expires
     */
    public function setValidUntil(int $validUntil): void
    {
        $this->validUntil = $validUntil;
    }

    /**
     * Gets the validity deadline for successful MFA verification
     *
     * This is not the pending challenge deadline or the expiry of a TOTP code.
     *
     * @return int|null Unix timestamp in seconds, or null when no validity deadline is assigned
     */
    public function getValidUntil(): ?int
    {
        return $this->validUntil;
    }
}
