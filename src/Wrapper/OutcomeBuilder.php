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

final class OutcomeBuilder
{
    private ?Packet $outcome;

    public function __construct(
        ?Packet $packet,
        ?LoggedInUserInfo $userInfo = null,
        array $persistenceDrivers = []
        )
    {
        $this->outcome = $this->buildOutcome($packet, $userInfo);
        if ($this->outcome !== null) {
            $this->attachAccessToken($this->outcome, $persistenceDrivers);
        }
    }

    private function buildOutcome(?Packet $packet, ?LoggedInUserInfo $userInfo = null): ?Packet
    {
        if ($answer = $this->checkSecurityPacket($packet)) {
            return $answer;
        } elseif ($answer = $this->checkMultiFactorPacket($packet)) {
            return $answer;
        } elseif ($answer = $this->checkThrottlingPacket($packet)) {
            return $answer;
        } elseif ($answer = $this->composeLoggedInUserPacket($userInfo, $packet?->getCallback())) {
            return $answer;
        } else {
            return $packet;
        }
    }

    private function checkSecurityPacket(?Packet $packet): ?SecurityPacket
    {
        if ($packet instanceof SecurityPacket) {
            if ($packet->getStatus() !== AuthenticationStatus::LOGIN_OK) {
                return $packet;
            }
        }
        return null;
    }

    private function checkMultiFactorPacket(?Packet $packet): ?MultiFactorPacket
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

    private function checkThrottlingPacket(?Packet $packet): ?ThrottlingPacket
    {
        if ($packet instanceof ThrottlingPacket) {
            return $packet;
        }
        return null;
    }

    private function composeLoggedInUserPacket(?LoggedInUserInfo $userInfo, ?string $callback): ?LoggedInUser
    {
        if ($userInfo !== null && $userInfo->getAuthenticatedStage()===AuthenticationStage::AUTHENTICATED) {
            $packet = new LoggedInUser($userInfo->getUserID());
            if ($callback !== null) {
                $packet->setCallback($callback);
            }
            return $packet;
        }
        return null;
    }

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
    
    public function getOutcome(): ?Packet
    {
        return $this->outcome;
    }
}