<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Configuration as SecurityConfiguration;
use Lucinda\WebSecurity\Configuration\RolesDetector;
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
 * Executes the configured request-security state machine
 *
 * Construction parses configuration, creates persistence and CSRF helpers,
 * restores existing authentication state, then evaluates primary
 * authentication, optional MFA, and authorization in that order. The first
 * actionable packet stops the remaining stages. Guest requests may continue
 * through authorization with no authenticated user ID.
 *
 * Authentication state is kept internal and represented publicly by Packet
 * subclasses. getOutcome() converts successful internal state into a
 * LoggedInUser packet, preserves actionable failure or transition packets,
 * and attaches an available bearer persistence token.
 *
 * The class decides security state but does not send redirects or HTTP
 * responses. The caller owns those outcome-dependent actions.
 *
 * @see Configuration
 * @see Request
 * @see \Lucinda\WebSecurity\Packets\Packet
 * @see \Lucinda\WebSecurity\Wrapper\Authentication
 * @see \Lucinda\WebSecurity\Wrapper\MultiFactorAuthentication
 * @see \Lucinda\WebSecurity\Wrapper\Authorization
 * @see \Lucinda\WebSecurity\Wrapper\OutcomeBuilder
 */
final class Wrapper
{
    /**
     * @var PersistenceDriver[] Configured persistence drivers in detection and save order
     */
    private array $persistenceDrivers = [];

    /**
     * Authentication state restored or produced while executing this request
     */
    private ?LoggedInUserInfo $userInfo = null;

    /**
     * Normalized request evaluated by every workflow stage
     */
    private Request $request;

    /**
     * Parsed security configuration shared by workflow wrappers
     */
    private SecurityConfiguration $configuration;

    /**
     * @var array<string,OAuth2Service> Provider services keyed by configured OAuth2 provider name
     */
    private array $oauth2Drivers;

    /**
     * OAuth2 state store, or null when OAuth2 authentication is not in use
     */
    private ?OAuth2State $oauth2State;

    /**
     * Pre-indexed XML role policy, or null when route-role authorization is not in use
     */
    private ?RolesDetector $rolesDetector = null;

    /**
     * CSRF token generator and validator bound to the current client IP
     */
    private CsrfToken $csrfToken;

    /**
     * First actionable internal workflow packet, or null when execution may continue
     */
    private ?Packet $outcome = null;

    /**
     * Builds dependencies, restores state, and executes the security workflow
     *
     * OAuth2 dependencies are required only when OAuth2 is configured. The role
     * detector is required only for XML route-role authorization and can be
     * prepared once by the caller from its routes document.
     *
     * @param \SimpleXMLElement $xml Complete application XML document containing `security`
     * @param Request $request Fully normalized current request
     * @param array<string,OAuth2Service> $oauth2Drivers Provider services keyed by configured provider name
     * @param OAuth2State|null $oauth2State One-time state store required by OAuth2 authentication
     * @param RolesDetector|null $rolesDetector Indexed route-role policy required by XML authorization
     * @throws \Throwable If configuration, persistence restoration, authentication, MFA, or authorization fails
     */
    public function __construct(
        \SimpleXMLElement $xml,
        Request $request,
        array $oauth2Drivers = [],
        ?OAuth2State $oauth2State = null,
        ?RolesDetector $rolesDetector = null
        )
    {
        $this->request = $request;
        $this->configuration = new SecurityConfiguration($xml);
        $this->oauth2Drivers = $oauth2Drivers;
        $this->oauth2State = $oauth2State;
        $this->rolesDetector = $rolesDetector;

        $pdd = new PersistenceDriversDetector($this->configuration->getPersistence(), $request->getIpAddress());
        $this->persistenceDrivers = $pdd->getPersistenceDrivers();

        $udd = new UserInfoDetector($this->persistenceDrivers, $request->getAccessToken());
        $this->userInfo = $udd->getUserInfo();

        $this->csrfToken = new CsrfToken($this->configuration->getCsrf(), $request->getIpAddress());
        $this->outcome = $this->execute();
    }

    /**
     * Executes authentication, MFA, and authorization in sequence
     *
     * A null stage result means execution should continue. Any packet is an
     * actionable state-machine result and is returned immediately without
     * evaluating later stages.
     *
     * @return Packet|null First actionable workflow packet, or null when all applicable stages allow execution
     * @throws \Throwable If any workflow stage fails unexpectedly
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
     * Runs primary authentication and synchronizes the resulting held user state
     *
     * @return Packet|null Authentication packet, or null when no handler matched or processing must continue to MFA
     * @throws \Throwable If authentication or its persistence transition fails
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
     * Runs configured MFA and synchronizes the resulting held user state
     *
     * @return Packet|null MFA or throttling packet, or null when MFA permits authorization to continue
     * @throws \Throwable If MFA evaluation or its persistence transition fails
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
     * Authorizes the request as an authenticated user or guest
     *
     * Only AUTHENTICATED state exposes a user ID to authorization. Pending MFA
     * state is represented as a guest if execution reaches this method.
     *
     * @return Packet|null Authorization failure packet, or null when access is allowed
     * @throws \Throwable If authorization configuration or a policy implementation fails
     */
    private function authorization(): ?Packet
    {
        $userID = ($this->userInfo?->getAuthenticatedStage() === AuthenticationStage::AUTHENTICATED)
        ? $this->userInfo->getUserID()
        : null;

        $driver = new AuthorizationWrapper(
            $this->configuration,
            $this->request,
            $this->rolesDetector,
            $userID
        );
        return $driver->run();
    }

    /**
     * Builds the caller-facing packet for the completed workflow
     *
     * This does not rerun authentication, MFA, or authorization. It may replace
     * terminal success with LoggedInUser, generate that user's CSRF token, and
     * attach an access token exposed by synchronizer-token persistence. Calling
     * the method repeatedly rebuilds this public representation.
     *
     * @return Packet|null Actionable or authenticated-user packet, or null when execution may continue as a guest
     * @throws \Throwable If final packet enrichment, including CSRF generation, fails
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
