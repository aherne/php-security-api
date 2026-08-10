<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Configuration as SecurityConfiguration;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Detectors\PersistenceDrivers as PersistenceDriversDetector;
use Lucinda\WebSecurity\Detectors\UserInfo as UserInfoDetector;
use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Packets\Packet;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\Wrapper\Authentication as AuthenticationWrapper;
use Lucinda\WebSecurity\Wrapper\MultiFactorAuthentication as MultiFactorAuthenticationWrapper;
use Lucinda\WebSecurity\Wrapper\Authorization as AuthorizationWrapper;
use Lucinda\WebSecurity\Packets\LoggedInUser;
use Lucinda\WebSecurity\Wrapper\OutcomeBuilder;

/**
 * Authenticates and authorizes based on contents of XML tag 'security'
 */
final class Wrapper
{
    /**
     * @var PersistenceDriver[]
     */
    private array $persistenceDrivers = [];
    private ?LoggedInUserInfo $userInfo = null;
    private Request $request;
    private SecurityConfiguration $configuration;
    /**
     * @var array<string,Oauth2Service>
     */
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
     * @param ?\SimpleXMLElement $routes
     */
    public function __construct(
        \SimpleXMLElement $xml,
        Request $request,
        array $oauth2Drivers = [],
        ?\SimpleXMLElement $routes = null
        )
    {
        $this->request = $request;
        $this->configuration = new SecurityConfiguration($xml);
        $this->oauth2Drivers = $oauth2Drivers;
        $this->routes = $routes;

        $pdd = new PersistenceDriversDetector($this->configuration->getPersistence(), $request->getIpAddress());
        $this->persistenceDrivers = $pdd->getPersistenceDrivers();

        $udd = new UserInfoDetector($this->persistenceDrivers, $request->getAccessToken());
        $this->userInfo = $udd->getUserInfo();

        $this->csrfToken = new CsrfToken($this->configuration->getCsrf(), $request->getIpAddress());
        $this->outcome = $this->execute();
    }

    /**
     * Executes the configured security workflow.
     *
     * @return SecurityPacket|MultiFactorPacket|ThrottlingPacket|LoggedInUser|null
     */
    private function execute(): SecurityPacket|MultiFactorPacket|ThrottlingPacket|LoggedInUser|null
    {
        $outcome = $this->authentication();
        if ($outcome !== null) {
            return $outcome;
        }

        if ($outcome = $this->multiFactorAuthentication()) {
            return $outcome;
        }

        if ($outcome = $this->authorization()) {
            return $outcome;
        }

        return null;
    }

    /**
     * Runs authentication.
     *
     * @return SecurityPacket|MultiFactorPacket|ThrottlingPacket|null
     */
    private function authentication(): SecurityPacket|MultiFactorPacket|ThrottlingPacket|null
    {
        $driver = new AuthenticationWrapper(
            $this->configuration,
            $this->request,
            $this->csrfToken,
            $this->persistenceDrivers,
            $this->oauth2Drivers,
            $this->userInfo
            );
        $outcome = $driver->run();
        $this->userInfo = $driver->getLoggedInUserInfo();
        return $outcome;
    }

    /**
     * Runs multi-factor authentication.
     *
     * @return MultiFactorPacket|ThrottlingPacket|null
     */
    private function multiFactorAuthentication(): MultiFactorPacket|ThrottlingPacket|null
    {
        $driver = new MultiFactorAuthenticationWrapper(
            $this->configuration,
            $this->request,
            $this->persistenceDrivers,
            $this->userInfo
            );
        $outcome = $driver->run();
        $this->userInfo = $driver->getLoggedInUserInfo();
        return $outcome;
    }

    /**
     * Runs authorization.
     *
     * @return ?SecurityPacket
     */
    private function authorization(): ?SecurityPacket
    {
        $userID = ($this->userInfo?->getAuthenticatedStage() === AuthenticationStage::AUTHENTICATED)
        ? $this->userInfo->getUserID()
        : null;

        $driver = new AuthorizationWrapper(
            $this->configuration,
            $this->request,
            $this->routes,
            $userID
        );
        return $driver->run();
    }

    /**
     * Gets outcome.
     *
     * @return SecurityPacket|MultiFactorPacket|ThrottlingPacket|LoggedInUser|null
     */
    public function getOutcome(): SecurityPacket|MultiFactorPacket|ThrottlingPacket|LoggedInUser|null
    {
        $builder = new OutcomeBuilder($this->outcome, $this->userInfo, $this->persistenceDrivers);
        return $builder->getOutcome();
    }

    /**
     * Gets CSRF token.
     *
     * @return string
     */
    public function getCsrfToken(): string
    {
        return $this->csrfToken->generate($this->userInfo?->getUserID());
    }
}
