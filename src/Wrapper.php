<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Configuration as SecurityConfiguration;
use Lucinda\WebSecurity\DAO\LoginThrottler;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Detectors\PersistenceDrivers as PersistenceDriversDetector;
use Lucinda\WebSecurity\Detectors\UserId;
use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Packets\Packet;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\PersistenceDriver as TokenPersistenceDriver;
use Lucinda\WebSecurity\Security\Authentication;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus as AuthenticationStatus;
use Lucinda\WebSecurity\Security\Authorization;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus as AuthorizationStatus;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus as MultiFactorAuthenticationStatus;

/**
 * Authenticates and authorizes based on contents of XML tag 'security'
 */
final class Wrapper
{
    /**
     * @var PersistenceDriver[]
     */
    private array $persistenceDrivers = [];
    private string|int|null $userID = null;
    private Request $request;
    private SecurityConfiguration $configuration;
    private ?LoginThrottler $loginThrottler;
    private array $oauth2Drivers;
    private ?\SimpleXMLElement $routes = null;
    private CsrfToken $csrfToken;
    private ?Packet $outcome = null;

    /**
     * Performs class logic by delegating to specialized methods
     *
     * @param  \SimpleXMLElement $xml
     * @param  Request           $request
     * @param  Oauth2Service[]   $oauth2Drivers
     * @param  ?LoginThrottler   $loginThrottler
     * @param ?\SimpleXMLElement $routes
     */
    public function __construct(
        \SimpleXMLElement $xml,
        Request $request,
        array $oauth2Drivers = [],
        ?LoginThrottler $loginThrottler = null,
        ?\SimpleXMLElement $routes = null
        )
    {
        $this->request = $request;
        $this->configuration = new SecurityConfiguration($xml);
        $this->loginThrottler = $loginThrottler;
        $this->oauth2Drivers = $oauth2Drivers;
        $this->routes = $routes;

        $pdd = new PersistenceDriversDetector($this->configuration->getPersistence(), $request->getIpAddress());
        $this->persistenceDrivers = $pdd->getPersistenceDrivers();

        $udd = new UserId($this->persistenceDrivers, $request->getAccessToken());
        $this->userID = $udd->getUserID();

        $this->csrfToken = new CsrfToken($this->configuration->getCsrf(), $request->getIpAddress());
        $this->outcome = $this->execute();
    }

    private function execute(): SecurityPacket|MultiFactorPacket|ThrottlingPacket|null
    {
        if ($outcome = $this->multiFactorAuthentication()) {
            return $outcome;
        }

        if ($outcome = $this->authentication()) {
            return $outcome;
        }

        if ($outcome = $this->authorization()) {
            return $outcome;
        }

        return $this->fallback();
    }

    private function multiFactorAuthentication(): MultiFactorPacket|ThrottlingPacket|null
    {
        $configuration = $this->configuration->getMultiFactorAuthentication();
        if ($configuration === null || $this->userID === null) {
            return null;
        }

        $validator = new MultiFactorAuthentication($configuration, $this->request, $this->userID);
        $outcome = $validator->getOutcome();
        if (!$outcome) {
            return null;
        }

        if ($outcome instanceof MultiFactorPacket && in_array($outcome->getStatus(), [MultiFactorAuthenticationStatus::SUCCEEDED, MultiFactorAuthenticationStatus::NOT_REQUIRED])) {
            $this->login();
        }
        return $outcome;
    }

    private function authentication(): SecurityPacket|MultiFactorPacket|ThrottlingPacket|null
    {
        $validator = new Authentication(
            $this->configuration->getAuthentication(),
            $this->request,
            $this->userID,
            $this->loginThrottler,
            $this->csrfToken,
            $this->oauth2Drivers
            );
        $outcome = $validator->getOutcome();
        if (!$outcome) {
            return null;
        }

        if ($outcome instanceof SecurityPacket && $outcome->getStatus() == AuthenticationStatus::PASSWORD_VERIFIED) {
            $this->userID = $outcome->getUserID();

            $multiFactorConfiguration = $this->configuration->getMultiFactorAuthentication();
            if ($multiFactorConfiguration === null) {
                $outcome->setStatus(AuthenticationStatus::LOGIN_OK);
                $this->login();
            } else {
                $validator = new MultiFactorAuthentication($multiFactorConfiguration, $this->request, $this->userID);
                if ($mfaOutcome = $validator->getOutcome()) {
                    return $mfaOutcome;
                }
            }
        } elseif ($outcome instanceof SecurityPacket && $outcome->getStatus() == AuthenticationStatus::LOGIN_OK) {
            $this->userID = $outcome->getUserID();
            $this->login();
        } elseif ($outcome instanceof SecurityPacket && $outcome->getStatus() == AuthenticationStatus::LOGOUT_OK) {
            $this->userID = null;
            $this->logout();
        }

        return $outcome;
    }

    private function authorization(): ?SecurityPacket
    {
        $validator = new Authorization(
            $this->configuration->getAuthorization(),
            $this->request,
            $this->userID,
            !empty($this->routes->routes) ? $this->routes : null
            );
        if ($outcome = $validator->getOutcome()) {
            if ($outcome->getStatus() == AuthorizationStatus::OK) {
                return null;
            }

            $callback = $outcome->getCallbackURI();
            if ($callback) {
                $callback = $this->request->getContextPath()."/".$callback;
            }
            return new SecurityPacket($outcome->getStatus(), $callback ?: null);
        }
        return null;
    }

    private function fallback(): ?SecurityPacket
    {
        if (!$this->userID) {
            return null;
        }

        $packet = new SecurityPacket(AuthorizationStatus::OK);
        $packet->setUserID($this->userID);
        return $packet;
    }

    private function login(): void
    {
        foreach ($this->persistenceDrivers as $persistenceDriver) {
            $persistenceDriver->save($this->userID);
        }
    }

    private function logout(): void
    {
        foreach ($this->persistenceDrivers as $persistenceDriver) {
            $persistenceDriver->clear();
        }
    }

    public function getOutcome(): SecurityPacket|MultiFactorPacket|ThrottlingPacket|null
    {
        return $this->outcome;
    }

    public function getUserID(): int|string|null
    {
        return $this->userID;
    }

    public function getCsrfToken(): string
    {
        return $this->csrfToken->generate($this->userID);
    }

    public function getAccessToken(): ?string
    {
        foreach ($this->persistenceDrivers as $driver) {
            if ($driver instanceof TokenPersistenceDriver) {
                return $driver->getAccessToken();
            }
        }
        return null;
    }
}
