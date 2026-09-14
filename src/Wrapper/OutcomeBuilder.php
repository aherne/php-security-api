<?php

namespace Lucinda\WebSecurity\Wrapper;

use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\PersistenceDriver as TokenPersistenceDriver;
use Lucinda\WebSecurity\Packets\LoggedInUser;
use Lucinda\WebSecurity\Packets\Packet;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus as MultiFactorAuthenticationStatus;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus as AuthenticationStatus;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\Detectors\CsrfToken;

/**
 * Binds workflow packets and authentication state into the parent Wrapper's final outcome
 *
 * Combines the stage outcome, held authentication state, CSRF generator,
 * and persistence drivers. Preserves actionable security, MFA, and throttling
 * packets; where appropriate, represents authenticated state as LoggedInUser
 * with a new CSRF token. Attaches an available authentication bearer token.
 *
 * Construction builds the outcome and may enrich the supplied packet itself.
 * It does not execute authentication, save persistence, or send a response.
 *
 * @internal
 * @see \Lucinda\WebSecurity\Wrapper::getOutcome()
 * @see \Lucinda\WebSecurity\Packets\Packet
 * @see \Lucinda\WebSecurity\Packets\LoggedInUser
 * @see \Lucinda\WebSecurity\Detectors\CsrfToken
 */
final class OutcomeBuilder
{
    private ?Packet $outcome;

    /**
     * Builds the final outcome from a workflow packet and authentication context
     *
     * May reuse the supplied packet and attach a persistence token to it.
     *
     * @param Packet|null $packet Outcome produced by a workflow stage, or null when no stage produced one
     * @param LoggedInUserInfo|null $userInfo Authentication state after workflow execution, or null for a guest
     * @param CsrfToken $csrfTokenDetector Generator for the authenticated user's CSRF token
     * @param \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver[] $persistenceDrivers Drivers inspected for an available bearer token
     * @throws \Throwable If CSRF token generation fails
     */
    public function __construct(
        ?Packet $packet,
        ?LoggedInUserInfo $userInfo,
        CsrfToken $csrfTokenDetector,
        array $persistenceDrivers = []
        )
    {
        $this->outcome = $this->buildOutcome($packet, $csrfTokenDetector, $userInfo);
        if ($this->outcome !== null) {
            $this->attachAccessToken($this->outcome, $persistenceDrivers);
        }
    }

    /**
     * Selects the stage outcome or composes an authenticated-user packet
     *
     * Retains security packets other than LOGIN_OK, MFA packets other than
     * SUCCEEDED or NOT_REQUIRED, and throttling packets. Otherwise attempts to
     * build LoggedInUser from authenticated state, preserving the input callback.
     * If no replacement can be built, returns the original packet.
     *
     * @param Packet|null $packet Original workflow outcome, or null when none was produced
     * @param CsrfToken $csrfTokenDetector Generator for the authenticated user's CSRF token
     * @param LoggedInUserInfo|null $userInfo Authentication state used to decide whether LoggedInUser can be built
     * @return Packet|null Preserved or composed outcome, or null when neither is available
     * @throws \Throwable If CSRF token generation fails
     */
    private function buildOutcome(
        ?Packet $packet,
        CsrfToken $csrfTokenDetector,
        ?LoggedInUserInfo $userInfo = null
        ): ?Packet
    {
        if ($answer = $this->checkSecurityPacket($packet)) {
            return $answer;
        } elseif ($answer = $this->checkMultiFactorPacket($packet)) {
            return $answer;
        } elseif ($answer = $this->checkThrottlingPacket($packet)) {
            return $answer;
        } elseif ($answer = $this->composeLoggedInUserPacket($userInfo, $csrfTokenDetector, $packet?->getCallback())) {
            return $answer;
        } else {
            return $packet;
        }
    }

    /**
     * Selects a security packet that should be preserved
     *
     * @param Packet|null $packet Workflow outcome to inspect
     * @return SecurityPacket|null Original security packet unless its status is LOGIN_OK; null otherwise
     */
    private function checkSecurityPacket(
        ?Packet $packet
        ): ?SecurityPacket
    {
        if ($packet instanceof SecurityPacket) {
            if ($packet->getStatus() !== AuthenticationStatus::LOGIN_OK) {
                return $packet;
            }
        }
        return null;
    }

    /**
     * Selects an MFA packet that should be preserved
     *
     * @param Packet|null $packet Workflow outcome to inspect
     * @return MultiFactorPacket|null Original MFA packet unless its status is SUCCEEDED or NOT_REQUIRED; null otherwise
     */
    private function checkMultiFactorPacket(
        ?Packet $packet
        ): ?MultiFactorPacket
    {
        if ($packet instanceof MultiFactorPacket) {
            if (!in_array(
                $packet->getStatus(),
                [
                    MultiFactorAuthenticationStatus::SUCCEEDED,
                    MultiFactorAuthenticationStatus::NOT_REQUIRED
                ],
                true
            )) {
                return $packet;
            }
        }
        return null;
    }

    /**
     * Selects a throttling packet that should be preserved
     *
     * @param Packet|null $packet Workflow outcome to inspect
     * @return ThrottlingPacket|null Original throttling packet, or null for another packet type or no packet
     */
    private function checkThrottlingPacket(
        ?Packet $packet
        ): ?ThrottlingPacket
    {
        if ($packet instanceof ThrottlingPacket) {
            return $packet;
        }
        return null;
    }

    /**
     * Builds an authenticated-user packet with a newly generated CSRF token
     *
     * Requires AUTHENTICATED state. Relies on upstream authentication processing;
     * does not recheck MFA freshness or resource authorization.
     *
     * @param LoggedInUserInfo|null $userInfo State to represent, or null when no identity is available
     * @param CsrfToken $csrfTokenDetector Generator for a CSRF token bound to the local user ID
     * @param string|null $callback Existing redirect destination to preserve, or null when none is specified
     * @return LoggedInUser|null Authenticated-user packet, or null for absent or pending-MFA state
     * @throws \Throwable If CSRF token generation fails
     */
    private function composeLoggedInUserPacket(
        ?LoggedInUserInfo $userInfo,
        CsrfToken $csrfTokenDetector,
        ?string $callback
        ): ?LoggedInUser
    {
        if ($userInfo !== null && $userInfo->getAuthenticatedStage()===AuthenticationStage::AUTHENTICATED) {
            $userID = $userInfo->getUserID();
            $packet = new LoggedInUser($userID, $csrfTokenDetector->generate($userID));
            if ($callback !== null) {
                $packet->setCallback($callback);
            }
            return $packet;
        }
        return null;
    }

    /**
     * Attaches the first available bearer token from token-based persistence
     *
     * Mutates the packet without issuing a new token or sending it to the client.
     * Leaves the packet unchanged if no driver exposes a non-empty token.
     *
     * @param Packet|null $packet Outcome to enrich; supplied non-null by the constructor
     * @param \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver[] $persistenceDrivers Drivers to inspect in order
     */
    private function attachAccessToken(?Packet $packet, array $persistenceDrivers): void {
        foreach ($persistenceDrivers as $driver) {
            if (
                $driver instanceof TokenPersistenceDriver
                && ($token = $driver->getAccessToken())
            ) {
                $packet->setAccessToken($token);
                return;
            }
        }
    }
    
    /**
     * Gets the final packet built during construction
     *
     * Does not rebuild the outcome or generate another CSRF token.
     *
     * @return Packet|null Built outcome, or null when no stage packet or authenticated-user packet is available
     */
    public function getOutcome(): ?Packet
    {
        return $this->outcome;
    }
}
