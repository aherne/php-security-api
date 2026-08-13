<?php

namespace Lucinda\WebSecurity\Wrapper;

use Lucinda\WebSecurity\Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication as SecurityMultiFactorAuthentication;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus as MultiFactorAuthenticationStatus;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver as RememberMePersistenceDriver;
use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;

final class MultiFactorAuthentication
{
    private Configuration $configuration;
    private Request $request;
    private array $persistenceDrivers;
    private ?LoggedInUserInfo $userInfo;
    

    public function __construct(
        Configuration $configuration,
        Request $request,
        array $persistenceDrivers,
        ?LoggedInUserInfo $userInfo = null
        )
    {
        $this->configuration = $configuration;
        $this->request = $request;
        $this->persistenceDrivers = $persistenceDrivers;
        $this->userInfo = $userInfo;
    }

    public function run(): MultiFactorPacket|ThrottlingPacket|null
    {
        $configuration = $this->configuration->getMultiFactorAuthentication();
        if ($configuration === null || $this->userInfo === null) {
            return null;
        }

        $validator = new SecurityMultiFactorAuthentication($configuration, $this->request, $this->userInfo);
        $outcome = $validator->getOutcome();
        if (!$outcome) {
            return null;
        }

        $status = $outcome->getStatus();

        if ($status === MultiFactorAuthenticationStatus::SUCCEEDED) {
            $validUntil = $outcome->getValidUntil(); // this is packet's valid until

            if ($validUntil === null) {
                throw new ConfigurationException(
                    "Successful MFA outcome must contain an expiration timestamp"
                );
            }

            $this->login($validUntil);
            return $outcome;
        } elseif ($status === MultiFactorAuthenticationStatus::NOT_REQUIRED) {
            if (
                $this->userInfo->getAuthenticatedStage()
                === AuthenticationStage::PENDING_MFA
            ) {
                $this->login(null);
                return $outcome;
            }

            // Already authenticated and MFA policy currently requires nothing.
            // Allow Wrapper::execute() to continue to authorization.
            return null;
        } elseif ($status === MultiFactorAuthenticationStatus::EXPIRED) {
            $this->userInfo = null;
            foreach ($this->persistenceDrivers as $persistenceDriver) {
                $persistenceDriver->clear();
            }
        }

        return $outcome;
    }

    private function login(?int $stageValidUntil): void
    {
        $wasTicked = $this->userInfo->rememberRequested();

        $this->userInfo = new LoggedInUserInfo(
            $this->userInfo->getUserID(),
            AuthenticationStage::AUTHENTICATED,
            $wasTicked,
            $stageValidUntil
        );
        foreach ($this->persistenceDrivers as $persistenceDriver) {
            if ($persistenceDriver instanceof RememberMePersistenceDriver && !$wasTicked) {
                continue; // do not save to remember me persistence driver unless remember me was actually ticked
            }
            $persistenceDriver->save($this->userInfo);
        }
    }


    public function getLoggedInUserInfo(): ?LoggedInUserInfo
    {
        return $this->userInfo;
    }
}