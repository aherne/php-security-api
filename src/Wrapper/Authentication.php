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
use Lucinda\WebSecurity\OAuth2State;
use Lucinda\WebSecurity\Packets\GuestUser;
use Lucinda\WebSecurity\PersistenceDrivers\AuthenticationStage;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver as RememberMePersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;

/**
 * Binds authentication processing to request context and persistence updates
 *
 * Connects the main configuration, current user state, CSRF helper, and
 * OAuth2 services/state store to Security\Authentication. Translates accepted
 * identity and logout outcomes into persistence operations through Coordinator,
 * including pending-MFA state and remember-me selection.
 *
 * Construction binds dependencies; run() executes authentication and may
 * change persisted state. The parent Wrapper reads the resulting user state
 * through getLoggedInUserInfo().
 *
 * @internal
 * @see \Lucinda\WebSecurity\Wrapper
 * @see \Lucinda\WebSecurity\Security\Authentication
 * @see Coordinator
 * @see LoggedInUserInfo
 */
final class Authentication
{
    private Configuration $configuration;
    private Request $request;
    private CsrfToken $csrfToken;
    private Coordinator $persistenceDrivers;
    private ?LoggedInUserInfo $userInfo;
    /**
     * @var array<string,\Lucinda\WebSecurity\OAuth2Service> Provider services keyed by configured provider name
     */
    private array $oauth2Drivers = [];
    private ?OAuth2State $oauth2State = null;

    /**
     * Binds authentication dependencies without executing the workflow
     *
     * @param Configuration $configuration Main security configuration containing authentication and MFA settings
     * @param Request $request Current request, including login parameters and remember-me selection
     * @param CsrfToken $csrfToken Generator and validator for authentication CSRF tokens
     * @param \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver[] $persistenceDrivers Drivers used to save or clear authentication state
     * @param array<string,\Lucinda\WebSecurity\OAuth2Service> $oauth2Drivers Provider services keyed by configured provider name
     * @param OAuth2State|null $oauth2State State store required when OAuth2 configuration is evaluated
     * @param LoggedInUserInfo|null $userInfo Existing authentication state, or null for a guest
     */
    public function __construct(
        Configuration $configuration,
        Request $request,
        CsrfToken $csrfToken,
        array $persistenceDrivers,
        array $oauth2Drivers = [],
        ?OAuth2State $oauth2State = null,
        ?LoggedInUserInfo $userInfo = null
        )
    {
        $this->configuration = $configuration;
        $this->request = $request;
        $this->csrfToken = $csrfToken;
        $this->persistenceDrivers = new Coordinator($persistenceDrivers);
        $this->oauth2Drivers = $oauth2Drivers;
        $this->oauth2State = $oauth2State;
        $this->userInfo = $userInfo;
    }
    
    /**
     * Executes authentication and applies accepted outcomes to persistence
     *
     * A verified identity becomes AUTHENTICATED when MFA is not configured,
     * or PENDING_MFA when further MFA evaluation is needed. The latter returns
     * null so the parent wrapper continues to MFA. Accepted logout clears the
     * held user state and requests cleanup of every persistence driver.
     *
     * @return SecurityPacket|MultiFactorPacket|ThrottlingPacket|GuestUser|null Authentication outcome, or null for no matching handler or handoff to MFA
     * @throws \Throwable If authentication processing, state creation, persistence, or cleanup fails
     */
    public function run(): SecurityPacket|MultiFactorPacket|ThrottlingPacket|GuestUser|null
    {
        $validator = new SecurityAuthentication(
            $this->configuration->getAuthentication(),
            $this->request,
            $this->userInfo!==null?$this->userInfo->getUserID():null,
            $this->csrfToken,
            $this->oauth2Drivers,
            $this->oauth2State
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
     * Creates and persists fully authenticated state from a successful login outcome
     *
     * Reads remember-me selection from the request and skips remember-me drivers
     * when it was not requested. Assigns the new held state before saving it.
     *
     * @param SecurityPacket $outcome Accepted login outcome carrying a non-empty local user ID
     * @throws \Throwable If authentication-state creation, persistence, or compensating cleanup fails
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
     * Creates and persists pending-MFA state after primary identity verification
     *
     * Records the remember-me preference for use after MFA completion, but
     * excludes remember-me drivers from the pending-state write. The pending
     * deadline is calculated from the current time and supplied duration.
     *
     * @param SecurityPacket $outcome Verified-identity outcome carrying a non-empty local user ID
     * @param int $pendingExpirationMFA Time allowed to complete MFA, in seconds from now
     * @throws \Throwable If authentication-state creation, persistence, or compensating cleanup fails
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
     * Requests cleanup of every authentication persistence driver
     *
     * Coordinator attempts all drivers and reports cleanup failures.
     *
     * @throws \Throwable If any driver fails to clear its authentication data
     */
    private function logout(): void
    {
        $this->persistenceDrivers->clear();
    }

    /**
     * Gets the authentication state currently held by this helper
     *
     * Before run(), returns the supplied state. Afterwards, the state may
     * represent completed authentication or pending MFA; this getter neither
     * loads persistence nor checks whether a previous failed save was completed.
     *
     * @return LoggedInUserInfo|null Currently held state, or null for absent or cleared user state
     */
    public function getLoggedInUserInfo(): ?LoggedInUserInfo
    {
        return $this->userInfo;
    }
}
