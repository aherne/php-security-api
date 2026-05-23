<?php

namespace Lucinda\WebSecurity\Authentication\OAuth2;

use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\ConfigurationException;
use Lucinda\WebSecurity\Authentication\ResultStatus;

/**
 * Encapsulates authentication via an OAuth2 provider
 *
 * @requires OAuth2Client API (https://github.com/aherne/oauth2client)
 */
class Authentication
{
    private VendorAuthenticationDAO $dao;
    /**
     * @var PersistenceDriver[]
     */
    private array $persistenceDrivers;

    /**
     * Creates an authentication object.
     *
     * @param  VendorAuthenticationDAO $dao                Forwards authentication checks to DB.
     * @param  PersistenceDriver[]     $persistenceDrivers List of drivers to persist user unique identifier into.
     * @throws ConfigurationException When persistence drivers are invalid.
     */
    public function __construct(VendorAuthenticationDAO $dao, array $persistenceDrivers)
    {
        // check argument that it's instance of PersistenceDriver
        foreach ($persistenceDrivers as $persistentDriver) {
            if (!($persistentDriver instanceof PersistenceDriver)) {
                throw new ConfigurationException("Items must be instanceof PersistenceDriver");
            }
        }

        $this->dao = $dao;
        $this->persistenceDrivers = $persistenceDrivers;
    }

    /**
     * Performs login by delegating to driver-specific OAuth2 implementation.
     *
     * @param  Driver $driver            Forwards retrieval of user information based on access token.
     * @param  string $authorizationCode Authorization code to use in retrieving access token
     * @return AuthenticationResult Encapsulates result of login attempt.
     */
    public function login(Driver $driver, string $authorizationCode): AuthenticationResult
    {
        $accessToken = $driver->getAccessToken($authorizationCode);
        // retrieve user information from oauth2 driver
        $userInformation = $driver->getUserInformation($accessToken);
        // query dao for a user id and an authorization code >> redirect to temporary page
        $userID = $this->dao->login($userInformation, $driver->getVendorName(), $accessToken);
        // save in persistence drivers
        if (empty($userID)) {
            return new AuthenticationResult(ResultStatus::LOGIN_FAILED);
        } else {
            // saves in persistence drivers
            foreach ($this->persistenceDrivers as $persistenceDriver) {
                $persistenceDriver->save($userID);
            }
            // returns result
            $result = new AuthenticationResult(ResultStatus::LOGIN_OK);
            $result->setUserID($userID);
            $result->setAccessToken($accessToken);
            return $result;
        }
    }

    /**
     * Performs a logout operation:
     * - informs DAO that user has logged out (which must empty token)
     * - removes user id from persistence drivers (if any)
     *
     * @return AuthenticationResult Encapsulates result of logout attempt.
     */
    public function logout(): AuthenticationResult
    {
        // detect user_id from persistence drivers
        $userID = null;
        foreach ($this->persistenceDrivers as $persistentDriver) {
            $userID = $persistentDriver->load();
            if ($userID) {
                break;
            }
        }
        if (!$userID) {
            return new AuthenticationResult(ResultStatus::LOGOUT_FAILED);
        } else {
            // should throw an exception if user is not already logged in, empty access token
            $this->dao->logout($userID);

            // clears data from persistence drivers
            foreach ($this->persistenceDrivers as $persistentDriver) {
                $persistentDriver->clear();
            }

            // returns result
            return new AuthenticationResult(ResultStatus::LOGOUT_OK);
        }
    }
}
