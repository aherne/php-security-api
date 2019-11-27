<?php
namespace Lucinda\WebSecurity\Authentication\OAuth2;

use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\Authentication\AuthenticationException;
use Lucinda\WebSecurity\Authentication\AuthenticationResultStatus;

/**
 * Encapsulates authentication via an OAuth2 provider
 *
 * @requires OAuth2Client API (https://github.com/aherne/oauth2client)
 */
class OAuth2Authentication
{
    private $dao;
    private $persistenceDrivers;
    
    /**
     * Creates an authentication object.
     *
     * @param OAuth2AuthenticationDAO $dao Forwards authentication checks to DB.
     * @param PersistenceDriver[] $persistenceDrivers List of drivers to persist user unique identifier into.
     * @throws AuthenticationException When persistence drivers are invalid.
     */
    public function __construct(OAuth2AuthenticationDAO $dao, array $persistenceDrivers): void
    {
        // check argument that it's instance of PersistenceDriver
        foreach ($persistenceDrivers as $persistentDriver) {
            if (!($persistentDriver instanceof PersistenceDriver)) {
                throw new AuthenticationException("Items must be instanceof PersistenceDriver");
            }
        }
        
        $this->dao = $dao;
        $this->persistenceDrivers = $persistenceDrivers;
    }
    
    /**
     * Performs login by delegating to driver-specific OAuth2 implementation.
     *
     * @param OAuth2Driver $driver Forwards retrieval of user information based on access token.
     * @param string $accessToken OAuth2 access token.
     * @param boolean $createUserIfNotExists Whether or not login should automatically creat user in DB if it doesn't exist already.
     * @return OAuth2AuthenticationResult Encapsulates result of login attempt.
     */
    public function login(OAuth2Driver $driver, string $accessToken, bool $createUserIfNotExists=true): OAuth2AuthenticationResult
    {
        // retrieve user information from oauth2 driver
        $userInformation = $driver->getUserInformation($accessToken);
        // query dao for a user id and an authorization code >> redirect to temporary page
        $userID = $this->dao->login($userInformation, $accessToken, $createUserIfNotExists);
        // save in persistence drivers
        if (empty($userID)) {
            $result = new OAuth2AuthenticationResult(AuthenticationResultStatus::LOGIN_FAILED);
            return $result;
        } else {
            // saves in persistence drivers
            foreach ($this->persistenceDrivers as $persistenceDriver) {
                $persistenceDriver->save($userID);
            }
            // returns result
            $result = new OAuth2AuthenticationResult(AuthenticationResultStatus::LOGIN_OK);
            $result->setUserID($userID);
            $result->setAccessToken($accessToken);
            return $result;
        }
    }
    
    /**
     * Performs a logout operation:
     * - informs DAO that user has logged out (which must empty token)
     * - removes user id from persistence drivers (if any)
     * @return OAuth2AuthenticationResult Encapsulates result of logout attempt.
     */
    public function logout(): OAuth2AuthenticationResult
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
            $result = new OAuth2AuthenticationResult(AuthenticationResultStatus::LOGOUT_FAILED);
            return $result;
        } else {
            // should throw an exception if user is not already logged in, empty access token
            $this->dao->logout($userID);
            
            // clears data from persistence drivers
            foreach ($this->persistenceDrivers as $persistentDriver) {
                $persistentDriver->clear($userID);
            }
            
            // returns result
            $result = new OAuth2AuthenticationResult(AuthenticationResultStatus::LOGOUT_OK);
            return $result;
        }
    }
}
