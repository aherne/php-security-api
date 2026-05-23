<?php

namespace Lucinda\WebSecurity\Authentication\XML;

use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\ConfigurationException;
use Lucinda\WebSecurity\Authentication\Result;
use Lucinda\WebSecurity\Authentication\ResultStatus;

/**
 * Encapsulates authentication via XML ACL
 */
class Authentication
{
    private \SimpleXMLElement $xml;
    /**
     * @var PersistenceDriver[]
     */
    private array $persistenceDrivers;

    /**
     * Creates a form authentication object.
     *
     * @param  \SimpleXMLElement   $xml
     * @param  PersistenceDriver[] $persistenceDrivers List of PersistentDriver entries that persist authenticated state.
     * @throws ConfigurationException If one of persistenceDrivers entries is not a PersistentDriver
     */
    public function __construct(\SimpleXMLElement $xml, array $persistenceDrivers = [])
    {
        // check argument that it's instance of PersistenceDriver
        foreach ($persistenceDrivers as $persistentDriver) {
            if (!($persistentDriver instanceof PersistenceDriver)) {
                throw new ConfigurationException("Items must be instanceof PersistenceDriver");
            }
        }

        // save pointers
        $this->xml = $xml;
        $this->persistenceDrivers = $persistenceDrivers;
    }

    /**
     * Performs a login operation:
     * - queries XML for an user id based on credentials
     * - saves user_id in persistence drivers (if any)
     *
     * @param  string $username Value of user name
     * @param  string $password Value of user password
     * @return Result Encapsulates result of login attempt.
     * @throws ConfigurationException If POST parameters are invalid.
     */
    public function login(string $username, string $password): Result
    {
        $dao = new UserAuthenticationXML($this->xml);
        $userID = $dao->login($username, $password);
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
            return new Result(ResultStatus::LOGOUT_FAILED);
        } else {
            // clears data from persistence drivers
            foreach ($this->persistenceDrivers as $persistentDriver) {
                $persistentDriver->clear();
            }

            // returns result
            return new Result(ResultStatus::LOGOUT_OK);
        }
    }
}
