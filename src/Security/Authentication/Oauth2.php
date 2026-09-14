<?php

namespace Lucinda\WebSecurity\Security\Authentication;

use Lucinda\WebSecurity\Configuration\Authentication\Oauth2 as Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Exception;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2 as Oauth2Configuration;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2\Provisioning;
use Lucinda\WebSecurity\DAO\OAuth2\Login as LoginDAO;
use Lucinda\WebSecurity\DAO\OAuth2\AutomaticProvisioning;
use Lucinda\WebSecurity\DAO\OAuth2\ApprovalProvisioning;
use Lucinda\WebSecurity\DAO\OAuth2\UserInformation;
use Lucinda\WebSecurity\OAuth2ApprovalStatus;
use Lucinda\WebSecurity\OAuth2Service;
use Lucinda\WebSecurity\OAuth2State;
use Lucinda\WebSecurity\Security\FailureReason;

/**
 * Executes provider login negotiation and local account resolution or provisioning
 *
 * Construction evaluates matching provider login routes. Initial requests
 * save a random provider-bound state and produce an authorization redirect.
 * Callbacks consume state before exchanging the code and resolving a local
 * account. Missing accounts follow the configured provisioning policy.
 *
 * Provider calls, state storage, and provisioning may have side effects.
 * A resolved identity produces IDENTITY_VERIFIED; MFA staging and
 * authentication persistence remain the enclosing wrapper's responsibility.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authentication\Oauth2
 * @see \Lucinda\WebSecurity\OAuth2Service
 * @see \Lucinda\WebSecurity\OAuth2State
 * @see \Lucinda\WebSecurity\DAO\OAuth2\Login
 */
final class Oauth2 extends Generic
{
    /**
     * @var LoginDAO|AutomaticProvisioning|ApprovalProvisioning DAO capability selected by the provisioning configuration
     */
    private LoginDAO $dao;
    private OAuth2State $state;

    /**
     * Constructs the OAuth2 handler and evaluates matching provider routes
     *
     * @param Configuration $configuration Parsed OAuth2 routes, DAO class, and provisioning policy
     * @param Request $request Current request to evaluate
     * @param int|string|null $userID Current local user ID, or null for a guest
     * @param array<string,OAuth2Service> $oauth2Drivers Provider services keyed by configured provider name
     * @param OAuth2State $oauth2State Store used to save and consume provider-bound login state
     * @throws Exception If a configured provider service was not supplied
     * @throws \Throwable If provider, state-store, randomness, or DAO processing fails
     */
    public function __construct(
        Configuration $configuration,
        Request $request,
        int|string|null $userID,
        array $oauth2Drivers,
        OAuth2State $oauth2State
        )
    {
        $this->request = $request;
        $this->userID = $userID;
        $this->state = $oauth2State;

        $daoClass = $configuration->getDAO();
        $this->dao = new $daoClass();

        $requestURL = $request->getUri();

        $drivers = $configuration->getDrivers();
        foreach ($drivers as $driver) {
            $driverName = $driver->getName();
            if (!isset($oauth2Drivers[$driverName])) {
                throw new Exception("External oauth2 driver not injected: ".$driverName);
            }

            if ($driver->getPageLogin() === $requestURL) {
                $this->outcome = $this->login($configuration, $driverName, $oauth2Drivers[$driverName]);
            }
        }
    }

    /**
     * Processes an initial authorization request or a provider callback
     *
     * Presence of code, error, or state identifies a callback. Callback state
     * must be accepted before handling provider errors or exchanging a code.
     * Expected validation and account-policy rejections become failure packets.
     *
     * @param Oauth2Configuration $configuration Parsed OAuth2 settings and callbacks
     * @param string $vendor Configured provider name used for state binding and local account lookup
     * @param OAuth2Service $service Provider client used for authorization, tokens, and remote user information
     * @return SecurityPacket|null Computed provider-login decision
     * @throws \Throwable If provider, state-store, randomness, or DAO processing fails
     */
    private function login(Oauth2Configuration $configuration, string $vendor, OAuth2Service $service): SecurityPacket|null
    {
        if (!empty($this->userID)) { // already logged in
            return new SecurityPacket(
                ResultStatus::DEFERRED,
                $this->getCallback($configuration->getTargetSuccess())
                );
        }

        $parameters = $this->request->getParameters();
        $isCallback = (
            array_key_exists("code", $parameters)
            || array_key_exists("error", $parameters)
            || array_key_exists("state", $parameters)
        );
        if (!$isCallback) {
            $state = bin2hex(random_bytes(32));
            $this->state->save(
                $state,
                $vendor,
                time() + $configuration->getStateExpiration()
            );
            return new SecurityPacket(
                ResultStatus::DEFERRED,
                $service->getAuthorizationCodeEndpoint($state)
                );
        } else {       
            $receivedState = $parameters["state"] ?? null;

            if (
                !is_string($receivedState)
                || $receivedState === ""
                || !$this->state->consume($receivedState, $vendor)
            ) {
                return $this->loginFailed($configuration, FailureReason::OAUTH_INVALID_STATE);
            }

            if (array_key_exists("error", $parameters)) {
                return $this->loginFailed($configuration, FailureReason::OAUTH_ERROR);
            }

            $code = $parameters["code"] ?? null;

            if (!is_string($code) || $code === "") {
                return $this->loginFailed($configuration, FailureReason::OAUTH_PROVIDER_REJECTED);
            }

            $accessToken = $service->getAccessToken($code);
            $userInformation = $service->getUserInfo($accessToken);
            
            $userID = $this->dao->resolve($userInformation, $vendor);

            if ($userID !== null) {
                return $this->identityVerified($configuration, $userID);
            }

            return match ($configuration->getProvisioning()) {
                Provisioning::EXISTING_ONLY =>
                    $this->loginFailed($configuration, FailureReason::OAUTH_ACCOUNT_UNLISTED),

                Provisioning::AUTOMATIC =>
                    $this->createAccount($configuration, $userInformation, $vendor),

                Provisioning::APPROVAL_REQUIRED =>
                    $this->requestApproval($configuration, $userInformation, $vendor),
            };
        }
    }

    /**
     * Requests automatic account provisioning after local account lookup failed
     *
     * Requires the configured DAO to implement AutomaticProvisioning.
     *
     * @param Oauth2Configuration $configuration Parsed automatic-provisioning settings and callbacks
     * @param UserInformation $userInformation Remote account information obtained from the provider
     * @param string $vendor Configured provider name identifying the remote account namespace
     * @return SecurityPacket IDENTITY_VERIFIED for a created account, or LOGIN_FAILED when creation is rejected
     * @throws \Throwable If the provisioning DAO fails
     */
    private function createAccount(Oauth2Configuration $configuration, UserInformation $userInformation, string $vendor): SecurityPacket
    {
        $userID = $this->dao->create($userInformation, $vendor);
        if ($userID === null) {
            return $this->loginFailed($configuration, FailureReason::OAUTH_REGISTRATION_REJECTED);
        } else {
            return $this->identityVerified($configuration, $userID);
        }
    }

    /**
     * Requests account approval after local account lookup failed
     *
     * Requires the configured DAO to implement ApprovalProvisioning.
     *
     * @param Oauth2Configuration $configuration Parsed approval-provisioning settings and callbacks
     * @param UserInformation $userInformation Remote account information obtained from the provider
     * @param string $vendor Configured provider name identifying the remote account namespace
     * @return SecurityPacket LOGIN_PENDING for pending approval, or LOGIN_FAILED when the request is rejected
     * @throws \Throwable If the approval DAO fails
     */
    private function requestApproval(Oauth2Configuration $configuration, UserInformation $userInformation, string $vendor): SecurityPacket
    {
        $status = $this->dao->requestApproval($userInformation, $vendor);
        return match ($status) {
            OAuth2ApprovalStatus::PENDING =>
                $this->pendingApproval($configuration),

            OAuth2ApprovalStatus::REJECTED =>
                $this->loginFailed($configuration, FailureReason::OAUTH_ACCOUNT_REJECTED),
        };
    }

    /**
     * Composes the verified-identity outcome without persisting a login
     *
     * @param Oauth2Configuration $configuration Parsed OAuth2 success callback
     * @param int|string $userID Non-empty local user ID resolved or created by the DAO
     * @return SecurityPacket IDENTITY_VERIFIED packet carrying the local user ID and success callback
     */
    private function identityVerified(Oauth2Configuration $configuration, int|string $userID): SecurityPacket
    {        
        $packet = new SecurityPacket(ResultStatus::IDENTITY_VERIFIED, $this->getCallback($configuration->getTargetSuccess()));
        $packet->setUserID($userID);
        return $packet;
    }

    /**
     * Composes an OAuth2 login rejection with a detailed failure reason
     *
     * @param Oauth2Configuration $configuration Parsed OAuth2 failure callback
     * @param FailureReason $failureReason Specific validation or account-policy rejection cause
     * @return SecurityPacket LOGIN_FAILED packet carrying the failure reason and callback
     */
    private function loginFailed(Oauth2Configuration $configuration, FailureReason $failureReason): SecurityPacket
    {        
        return new SecurityPacket(
            ResultStatus::LOGIN_FAILED,
            $this->getCallback($configuration->getTargetFailure()),
            $failureReason
            );
    }

    /**
     * Composes the pending-account-approval outcome
     *
     * @param Oauth2Configuration $configuration Parsed OAuth2 pending-approval callback
     * @return SecurityPacket LOGIN_PENDING packet without an authenticated user ID
     */
    private function pendingApproval(Oauth2Configuration $configuration): SecurityPacket
    {        
        return new SecurityPacket(
            ResultStatus::LOGIN_PENDING,
            $this->getCallback($configuration->getTargetPending())
            );
    }
}
