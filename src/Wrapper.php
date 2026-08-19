<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Configuration as SecurityConfiguration;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Detectors\PersistenceDrivers as PersistenceDriversDetector;
use Lucinda\WebSecurity\Detectors\UserInfo as UserInfoDetector;
use Lucinda\WebSecurity\Packets\Packet;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\Wrapper\Authentication as AuthenticationWrapper;
use Lucinda\WebSecurity\Wrapper\MultiFactorAuthentication as MultiFactorAuthenticationWrapper;
use Lucinda\WebSecurity\Wrapper\Authorization as AuthorizationWrapper;
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
     * @var array<string,OAuth2Service>
     */
    private array $oauth2Drivers;
    private ?OAuth2State $oauth2State;
    private ?\SimpleXMLElement $routes = null;
    private CsrfToken $csrfToken;
    private ?Packet $outcome = null;

    /**
     * Performs class logic by delegating to specialized methods
     *
     * @param \SimpleXMLElement $xml
     * @param Request           $request
     * @param OAuth2Service[]   $oauth2Drivers
     * @param ?OAuth2State      $oauth2State
     * @param ?\SimpleXMLElement $routes
     */
    public function __construct(
        \SimpleXMLElement $xml,
        Request $request,
        array $oauth2Drivers = [],
        ?OAuth2State $oauth2State = null,
        ?\SimpleXMLElement $routes = null
        )
    {
        $this->request = $request;
        $this->configuration = new SecurityConfiguration($xml);
        $this->oauth2Drivers = $oauth2Drivers;
        $this->oauth2State = $oauth2State;
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
     * @return ?Packet
     */
    private function execute(): ?Packet
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
     * @return ?Packet
     */
    private function authentication(): ?Packet
    {
        $driver = new AuthenticationWrapper(
            $this->configuration,
            $this->request,
            $this->csrfToken,
            $this->persistenceDrivers,
            $this->oauth2Drivers,
            $this->oauth2State,
            $this->userInfo
            );
        $outcome = $driver->run();
        $this->userInfo = $driver->getLoggedInUserInfo();
        return $outcome;
    }

    /**
     * Runs multi-factor authentication.
     *
     * @return ?Packet
     */
    private function multiFactorAuthentication(): ?Packet
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
     * @return ?Packet
     */
    private function authorization(): ?Packet
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
     * @return ?Packet
     */
    public function getOutcome(): ?Packet
    {
        $builder = new OutcomeBuilder(
            $this->outcome,
            $this->userInfo,
            $this->csrfToken,
            $this->persistenceDrivers
            );
        return $builder->getOutcome();
    }
}
