<?php

namespace Lucinda\WebSecurity\Wrapper;

use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\PersistenceDriver as TokenPersistenceDriver;
use Lucinda\WebSecurity\Packets\LoggedInUser;

use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus as MultiFactorAuthenticationStatus;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus as AuthenticationStatus;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;

final class OutcomeBuilder
{
    private SecurityPacket|MultiFactorPacket|ThrottlingPacket|LoggedInUser|null $outcome;

    public function __construct(
        SecurityPacket|MultiFactorPacket|ThrottlingPacket|null $packet,
        ?LoggedInUserInfo $userInfo = null,
        array $persistenceDrivers = []
        )
    {
        if ($answer = $this->checkSecurityPacket($packet)) {
            $this->outcome = $answer;
        } elseif ($answer = $this->checkMultiFactorPacket($packet)) {
            $this->outcome = $answer;
        } elseif ($answer = $this->checkThrottlingPacket($packet)) {
            $this->outcome = $answer;
        } elseif ($answer = $this->composeLoggedInUserPacket($userInfo, $persistenceDrivers, $this->outcome->getCallback())) {
            $this->outcome = $answer;
        } else {
            $this->outcome = $packet;
        }
    }

    private function checkSecurityPacket(SecurityPacket|MultiFactorPacket|ThrottlingPacket|null $packet): ?SecurityPacket
    {
        if ($packet instanceof SecurityPacket) {
            if ($packet->getStatus() !== AuthenticationStatus::LOGIN_OK) {
                return $packet;
            }
        }
        return null;
    }

    private function checkMultiFactorPacket(SecurityPacket|MultiFactorPacket|ThrottlingPacket|null $packet): ?MultiFactorPacket
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

    private function checkThrottlingPacket(SecurityPacket|MultiFactorPacket|ThrottlingPacket|null $packet): ?ThrottlingPacket
    {
        if ($packet instanceof ThrottlingPacket) {
            return $packet;
        }
        return null;
    }

    private function composeLoggedInUserPacket(
        ?LoggedInUserInfo $userInfo,
        array $persistenceDrivers,
        ?string $callback
        ): ?LoggedInUser
    {
        if ($userInfo !== null && $userInfo->getAuthenticatedStage()===AuthenticationStage::AUTHENTICATED) {
            $packet = new LoggedInUser($userInfo->getUserID());
            if ($this->outcome !== null) {
                $packet->setCallback($callback);
            }
            foreach ($persistenceDrivers as $driver) {
                if ($driver instanceof TokenPersistenceDriver) {
                    if ($token = $driver->getAccessToken()) {
                        $packet->setAccessToken($token);
                    }
                }
            }
            return $packet;
        }
        return null;
    }
    
    public function getOutcome(): SecurityPacket|MultiFactorPacket|ThrottlingPacket|LoggedInUser|null
    {
        return $this->outcome;
    }
}