<?php

namespace Lucinda\WebSecurity\Security\Authentication;

use Lucinda\WebSecurity\Configuration\Authentication\Oauth2 as Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\DAO\Oauth2Authentication;
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
    private Oauth2Authentication $dao;

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

        if ($configuration->getPageLogout() === $requestURL) {
            $this->outcome = $this->logout($configuration);
        }       

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
        if ($this->userID !== null) { // already logged in
            return new SecurityPacket(
                ResultStatus::DEFERRED,
                $this->getCallback($configuration->getTargetLoginSuccess())
                );
        }

        $parameters = $this->request->getParameters();
        if (empty($parameters["code"])) {
            return new SecurityPacket(
                ResultStatus::DEFERRED,
                $service->getAuthorizationCodeEndpoint()
                );
        } else {
            $accessToken = $service->getAccessToken($parameters["code"]);
            $userInformation = $service->getUserInfo($accessToken);
            $outcome = $this->dao->login($userInformation, $vendor, $accessToken);
            if ($outcome !== null) {
                $packet = new SecurityPacket(ResultStatus::LOGIN_OK, $this->getCallback($configuration->getTargetLoginSuccess()));
                $packet->setUserID($outcome);
                return $packet;
            } else {
                return new SecurityPacket(ResultStatus::LOGIN_FAILED, $this->getCallback($configuration->getTargetLoginFailure()));
            }
        }
    }

    /**
     * Processes logout.
     *
     * @param Oauth2Configuration $configuration
     * @return SecurityPacket
     */
    private function logout(Oauth2Configuration $configuration): SecurityPacket
    {
        if ($this->userID === null) { // already logged out
            return new SecurityPacket(
                ResultStatus::DEFERRED,
                $this->getCallback($configuration->getTargetLogoutSuccess())
                );
        }

        if ($this->dao->logout($this->userID)) {
            return new SecurityPacket(ResultStatus::LOGOUT_OK, $this->getCallback($configuration->getTargetLogoutSuccess()));
        } else {
            return new SecurityPacket(ResultStatus::LOGOUT_FAILED, $this->getCallback($configuration->getTargetLogoutFailure()));
        }
    }
}
