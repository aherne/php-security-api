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
use Lucinda\WebSecurity\Packets\GuestUser;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\Coordinator;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver as RememberMePersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;

final class Authentication
{
    private Configuration $configuration;
    private Request $request;
    private CsrfToken $csrfToken;
    private Coordinator $persistenceDrivers;
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
        $this->persistenceDrivers = new Coordinator($persistenceDrivers);
        $this->oauth2Drivers = $oauth2Drivers;
        $this->userInfo = $userInfo;
    }
    
    /**
     * Runs authentication.
     *
     * @return SecurityPacket|MultiFactorPacket|ThrottlingPacket|GuestUser|null
     */
    public function run(): SecurityPacket|MultiFactorPacket|ThrottlingPacket|GuestUser|null
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
                $this->login($outcome);
            } else {
                $this->loginWithMFA($outcome, $multiFactorConfiguration->getPendingExpiration());
                return null; // let next MFA stage handle it
            }
        } elseif ($outcome instanceof SecurityPacket && $outcome->getStatus() == AuthenticationStatus::LOGIN_OK) {
            $this->login($outcome);
        } elseif ($outcome instanceof SecurityPacket && $outcome->getStatus() == AuthenticationStatus::LOGOUT_OK) {
            $this->userInfo = null;
            $this->logout();
        }

        return $outcome;
    }

    /**
     * Registers login.
     *
     * @param SecurityPacket $outcome
     */
    private function login(SecurityPacket $outcome): void
    {
        $object = new RememberMeTicked($this->configuration, $this->request);
        $this->userInfo = new LoggedInUserInfo(
            $outcome->getUserID(),
            AuthenticationStage::AUTHENTICATED,
            $object->getTicked()
            );
        $this->persistenceDrivers->save($this->userInfo, function($persistenceDriver) use($object) {
            return $persistenceDriver instanceof RememberMePersistenceDriver && !$object->getTicked();
        });
    }

    /**
     * Registers pending MFA-validated login.
     *
     * @param SecurityPacket $outcome
     * @param int $pendingExpirationMFA
     */
    private function loginWithMFA(SecurityPacket $outcome, int $pendingExpirationMFA): void
    {
        $object = new RememberMeTicked($this->configuration, $this->request);
        $this->userInfo = new LoggedInUserInfo(
            $outcome->getUserID(),
            AuthenticationStage::PENDING_MFA,
            $object->getTicked(),
            (time() + $pendingExpirationMFA)
            );
        $this->persistenceDrivers->save($this->userInfo, function($persistenceDriver) {
            return $persistenceDriver instanceof RememberMePersistenceDriver;
        });
    }

    /**
     * Processes logout.
     */
    private function logout(): void
    {
        $this->persistenceDrivers->clear();
    }

    /**
     * Gets authenticated user info
     * 
     * @return LoggedInUserInfo|null
     */
    public function getLoggedInUserInfo(): ?LoggedInUserInfo
    {
        return $this->userInfo;
    }
}
