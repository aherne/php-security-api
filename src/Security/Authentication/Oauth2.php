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


/**
 * Encapsulates OAuth2 logic.
 */
final class Oauth2 extends Generic
{
    /** @var AutomaticProvisioning|ApprovalProvisioning|LoginDAO $dao */
    private LoginDAO $dao;

    /**
     * Sets up object state.
     *
     * @param Configuration $configuration
     * @param Request $request
     * @param int|string|null $userID
     * @param array $oauth2Drivers
     */
    public function __construct(
        Configuration $configuration,
        Request $request,
        int|string|null $userID,
        array $oauth2Drivers
        )
    {
        $this->request = $request;
        $this->userID = $userID;

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
     * Processes login.
     *
     * @param Oauth2Configuration $configuration
     * @param string $vendor
     * @param OAuth2Service $service
     * @return SecurityPacket|null
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
        if (empty($parameters["code"])) {
            $state = bin2hex(random_bytes(32));
            $service->produceState($state); // duration is managed internally
            return new SecurityPacket(
                ResultStatus::DEFERRED,
                $service->getAuthorizationCodeEndpoint($state)
                );
        } else {
            $expectedState = $service->consumeState();
            $receivedState = $parameters["state"] ?? null;
            if (
                !is_string($expectedState)
                || $expectedState === ""
                || !is_string($receivedState)
                || !hash_equals($expectedState, $receivedState)
            ) {
                throw new Exception("Invalid OAuth2 state!");
            }

            $accessToken = $service->getAccessToken($parameters["code"]);
            $userInformation = $service->getUserInfo($accessToken);
            
            $userID = $this->dao->resolve($userInformation, $vendor);

            if ($userID !== null) {
                return $this->identityVerified($configuration, $userID);
            }

            return match ($configuration->getProvisioning()) {
                Provisioning::EXISTING_ONLY =>
                    $this->loginFailed($configuration),

                Provisioning::AUTOMATIC =>
                    $this->createAccount($configuration, $userInformation, $vendor),

                Provisioning::APPROVAL_REQUIRED =>
                    $this->requestApproval($configuration, $userInformation, $vendor),
            };
        }
    }

    private function createAccount(Oauth2Configuration $configuration, UserInformation $userInformation, string $vendor): SecurityPacket
    {
        $userID = $this->dao->create($userInformation, $vendor);
        if ($userID === null) {
            return $this->loginFailed($configuration);
        } else {
            return $this->identityVerified($configuration, $userID);
        }
    }

    private function requestApproval(Oauth2Configuration $configuration, UserInformation $userInformation, string $vendor): SecurityPacket
    {
        $status = $this->dao->requestApproval($userInformation, $vendor);
        return match ($status) {
            OAuth2ApprovalStatus::PENDING =>
                $this->pendingApproval($configuration),

            OAuth2ApprovalStatus::REJECTED =>
                $this->loginFailed($configuration),
        };
    }

    private function identityVerified(Oauth2Configuration $configuration, int|string $userID): SecurityPacket
    {        
        $packet = new SecurityPacket(ResultStatus::IDENTITY_VERIFIED, $this->getCallback($configuration->getTargetSuccess()));
        $packet->setUserID($userID);
        return $packet;
    }

    private function loginFailed(Oauth2Configuration $configuration): SecurityPacket
    {        
        return new SecurityPacket(ResultStatus::LOGIN_FAILED, $this->getCallback($configuration->getTargetFailure()));
    }

    private function pendingApproval(Oauth2Configuration $configuration): SecurityPacket
    {        
        return new SecurityPacket(ResultStatus::LOGIN_PENDING, $this->getCallback($configuration->getTargetPending()));
    }
}
