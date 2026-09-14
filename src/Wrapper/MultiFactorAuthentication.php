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

/**
 * Binds MFA outcomes to authentication-stage transitions and persistence
 *
 * Connects the main configuration, request, and current authentication state
 * to Security\MultiFactorAuthentication. Persists completed authentication
 * after successful MFA or a pending user's NOT_REQUIRED decision, and clears
 * authentication state when the pending-MFA deadline expires.
 *
 * Construction binds dependencies; run() executes MFA and persistence updates.
 * The parent Wrapper reads the resulting state through getLoggedInUserInfo().
 *
 * @internal
 * @see \Lucinda\WebSecurity\Wrapper
 * @see \Lucinda\WebSecurity\Security\MultiFactorAuthentication
 * @see Coordinator
 * @see LoggedInUserInfo
 */
final class MultiFactorAuthentication
{
    private Configuration $configuration;
    private Request $request;
    private Coordinator $persistenceDrivers;
    private ?LoggedInUserInfo $userInfo;
    

    /**
     * Binds MFA dependencies without executing verification or persistence
     *
     * @param Configuration $configuration Main security configuration containing MFA settings
     * @param Request $request Current request supplying MFA route, code, and client IP
     * @param \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver[] $persistenceDrivers Drivers used to save or clear authentication state
     * @param LoggedInUserInfo|null $userInfo Pending or authenticated state to evaluate, or null for a guest
     */
    public function __construct(
        Configuration $configuration,
        Request $request,
        array $persistenceDrivers,
        ?LoggedInUserInfo $userInfo = null
        )
    {
        $this->configuration = $configuration;
        $this->request = $request;
        $this->persistenceDrivers = new Coordinator($persistenceDrivers);
        $this->userInfo = $userInfo;
    }

    /**
     * Executes MFA and applies completion or expiry to authentication persistence
     *
     * Successful verification requires a validity timestamp. NOT_REQUIRED
     * promotes a pending user without an MFA freshness deadline; an already
     * authenticated user continues without an MFA packet. Expired pending state
     * is cleared locally and through all persistence drivers.
     *
     * @return MultiFactorPacket|ThrottlingPacket|null MFA outcome, or null when MFA is unconfigured, user state is absent, or no further MFA handling is needed
     * @throws ConfigurationException If a successful MFA packet lacks its validity timestamp
     * @throws \Throwable If MFA processing, persistence, or cleanup fails
     */
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
            $this->persistenceDrivers->clear();
        }

        return $outcome;
    }

    /**
     * Promotes the held user state to authenticated and persists it
     *
     * Preserves the recorded remember-me preference and skips remember-me
     * drivers when it was not requested. Assigns the new state before saving.
     *
     * @param int|null $stageValidUntil MFA freshness deadline as a Unix timestamp in seconds, or null when MFA is not required
     * @throws \Throwable If authentication-state creation, persistence, or compensating cleanup fails
     */
    private function login(?int $stageValidUntil): void
    {
        $wasTicked = $this->userInfo->rememberRequested();

        $this->userInfo = new LoggedInUserInfo(
            $this->userInfo->getUserID(),
            AuthenticationStage::AUTHENTICATED,
            $wasTicked,
            $stageValidUntil
        );
        $this->persistenceDrivers->save($this->userInfo, function($persistenceDriver) use($wasTicked) {
            return $persistenceDriver instanceof RememberMePersistenceDriver && !$wasTicked;
        });
    }

    /**
     * Gets the authentication state currently held by this helper
     *
     * Before run(), returns the supplied state. This getter does not reload
     * persistence or verify whether a previous failed save was completed.
     *
     * @return LoggedInUserInfo|null Currently held pending or authenticated state, or null when absent or cleared
     */
    public function getLoggedInUserInfo(): ?LoggedInUserInfo
    {
        return $this->userInfo;
    }
}
