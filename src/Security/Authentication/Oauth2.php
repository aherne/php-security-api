<?php

namespace Lucinda\WebSecurity\Security\Authentication;

use Lucinda\WebSecurity\Configuration\Authentication\Oauth2 as Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\DAO\Oauth2Login as LoginDAO;
use Lucinda\WebSecurity\Security\Exception;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2 as Oauth2Configuration;
use Lucinda\WebSecurity\Oauth2Service;


/**
 * Encapsulates OAuth2 logic.
 */
final class Oauth2 extends Generic
{
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
     * @param Oauth2Service $service
     * @return SecurityPacket|null
     */
    private function login(Oauth2Configuration $configuration, string $vendor, Oauth2Service $service): SecurityPacket|null
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
            $outcome = $this->dao->login($userInformation, $vendor);
            if (!empty($outcome)) {
                $packet = new SecurityPacket(ResultStatus::IDENTITY_VERIFIED, $this->getCallback($configuration->getTargetSuccess()));
                $packet->setUserID($outcome);
                return $packet;
            } else {
                return new SecurityPacket(ResultStatus::LOGIN_FAILED, $this->getCallback($configuration->getTargetFailure()));
            }
        }
    }
}
