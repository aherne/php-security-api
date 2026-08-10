<?php

namespace Lucinda\WebSecurity\Wrapper;

use Lucinda\WebSecurity\Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\Security\Authentication as SecurityAuthentication;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus as AuthenticationStatus;
use Lucinda\WebSecurity\Detectors\RememberMeTicked;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver as RememberMePersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;

final class Authentication
{
    private Configuration $configuration;
    private Request $request;
    private CsrfToken $csrfToken;
    private array $persistenceDrivers;
    private ?LoggedInUserInfo $userInfo;
    private array $oauth2Drivers = [];

    public function __construct(
        Configuration $configuration,
        Request $request,
        CsrfToken $csrfToken,
        array $persistenceDrivers,
        array $oauth2Drivers = [],
        ?LoggedInUserInfo $userInfo = null
        )
    {
        $this->configuration = $configuration;
        $this->request = $request;
        $this->csrfToken = $csrfToken;
        $this->persistenceDrivers = $persistenceDrivers;
        $this->oauth2Drivers = $oauth2Drivers;
        $this->userInfo = $userInfo;
    }
    
    /**
     * Runs authentication.
     *
     * @return SecurityPacket|MultiFactorPacket|ThrottlingPacket|null
     */
    public function run(): SecurityPacket|MultiFactorPacket|ThrottlingPacket|null
    {
        $validator = new SecurityAuthentication(
            $this->configuration->getAuthentication(),
            $this->request,
            $this->userInfo!==null?$this->userInfo->getUserID():null,
            $this->csrfToken,
            $this->oauth2Drivers
            );
        $outcome = $validator->getOutcome();
        if (!$outcome) {
            return null;
        }

        if ($outcome instanceof SecurityPacket && $outcome->getStatus() == AuthenticationStatus::IDENTITY_VERIFIED) {
            $multiFactorConfiguration = $this->configuration->getMultiFactorAuthentication();
            if ($multiFactorConfiguration === null) {
                $outcome->setStatus(AuthenticationStatus::LOGIN_OK);
                $this->login($outcome, AuthenticationStage::AUTHENTICATED);
            } else {
                $this->login($outcome, AuthenticationStage::PENDING_MFA);
                return null; // let next MFA stage handle it
            }
        } elseif ($outcome instanceof SecurityPacket && $outcome->getStatus() == AuthenticationStatus::LOGIN_OK) {
            $this->login($outcome, AuthenticationStage::AUTHENTICATED);
        } elseif ($outcome instanceof SecurityPacket && $outcome->getStatus() == AuthenticationStatus::LOGOUT_OK) {
            $this->userInfo = null;
            $this->logout();
        }

        return $outcome;
    }

    /**
     * Processes login.
     *
     */
    private function login(SecurityPacket $outcome, AuthenticationStage $authenticationStage): void
    {
        $object = new RememberMeTicked($this->configuration, $this->request);
        $this->userInfo = new LoggedInUserInfo($outcome->getUserID(), $authenticationStage, $object->getTicked());
        foreach ($this->persistenceDrivers as $persistenceDriver) {
            if (
                $persistenceDriver instanceof RememberMePersistenceDriver
                && (
                    $authenticationStage === AuthenticationStage::PENDING_MFA
                    || !$object->getTicked()
                )
            ) {
                continue;
            }
            $persistenceDriver->save($this->userInfo);
        }
    }

    /**
     * Processes logout.
     *
     */
    private function logout(): void
    {
        foreach ($this->persistenceDrivers as $persistenceDriver) {
            $persistenceDriver->clear();
        }
    }

    public function getLoggedInUserInfo(): ?LoggedInUserInfo
    {
        return $this->userInfo;
    }
}