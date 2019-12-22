<?php
namespace Lucinda\WebSecurity\Authentication\DAO;

use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\Authentication\Exception;
use Lucinda\WebSecurity\Authentication\Result;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver as RememberMePersistenceDriver;
use Lucinda\WebSecurity\Authentication\ResultStatus;

/**
 * Encapsulates authentication via data sent by POST through a html form
 */
class Authentication
{
    private $dao;
    private $persistenceDrivers;
    
    /**
     * Creates a form authentication object.
     *
     * @param UserAuthenticationDAO $dao Forwards operations to database via a DAO.
     * @param PersistenceDriver[] $persistenceDrivers List of PersistentDriver entries that allow authenticated state to persist between requests.
     * @throws Exception If one of persistenceDrivers entries is not a PersistentDriver
     */
    public function __construct(UserAuthenticationDAO $dao, array $persistenceDrivers = array()): void
    {
        // check argument that it's instance of PersistenceDriver
        foreach ($persistenceDrivers as $persistentDriver) {
            if (!($persistentDriver instanceof PersistenceDriver)) {
                throw new Exception("Items must be instanceof PersistenceDriver");
            }
        }
        
        // save pointers
        $this->dao = $dao;
        $this->persistenceDrivers = $persistenceDrivers;
    }
    
    /**
     * Performs a login operation:
     * - queries DAO for an user id based on credentials
     * - saves user_id in persistence drivers (if any)
     *
     * @param string $username Value of user name
     * @param string $password Value of user password
     * @param boolean $rememberMe Value of remember me option (if any)
     * @return Result Encapsulates result of login attempt.
     * @throws Exception If POST parameters are invalid.
     */
    public function login(string $username, string $password, bool $rememberMe=null): Result
    {
        // do no persist into RememberMePersistenceDriver unless "remember me" is active
        if (!$rememberMe) {
            foreach ($this->persistenceDrivers as $i=>$persistenceDriver) {
                if ($persistenceDriver instanceof RememberMePersistenceDriver) {
                    unset($this->persistenceDrivers[$i]);
                    break;
                }
            }
        }
        
        // perform login
        $userID = $this->dao->login($username, $password);
        if (empty($userID)) {
            $result = new Result(ResultStatus::LOGIN_FAILED);
            return $result;
        } else {
            // saves in persistence drivers
            foreach ($this->persistenceDrivers as $persistenceDriver) {
                $persistenceDriver->save($userID);
            }
            // returns result
            $result = new Result(ResultStatus::LOGIN_OK);
            $result->setUserID($userID);
            return $result;
        }
    }
    
    /**
     * Performs a logout operation:
     * - informs DAO that user has logged out
     * - removes user id from persistence drivers (if any)
     *
     * @return Result
     */
    public function logout(): Result
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
            $result = new Result(ResultStatus::LOGOUT_FAILED);
            return $result;
        } else {
            // should throw an exception if user is not already logged in
            $this->dao->logout($userID);
            
            // clears data from persistence drivers
            foreach ($this->persistenceDrivers as $persistentDriver) {
                $persistentDriver->clear($userID);
            }
            
            // returns result
            $result = new Result(ResultStatus::LOGOUT_OK);
            return $result;
        }
    }
}
