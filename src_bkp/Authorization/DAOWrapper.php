<?php

namespace Lucinda\WebSecurity\Authorization;

use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\ConfigurationException;
use Lucinda\WebSecurity\Authorization\DAO\UserAuthorizationDAO;
use Lucinda\WebSecurity\Authorization\DAO\PageAuthorizationDAO;
use Lucinda\WebSecurity\Authorization\DAO\Authorization;

/**
 * Binds DAOAuthorization @ SECURITY-API to settings from configuration.xml @ SERVLETS-API then performs request
 * authorization via database.
 */
class DAOWrapper extends Wrapper
{
    public const DEFAULT_LOGGED_IN_PAGE = "index";
    public const DEFAULT_LOGGED_OUT_PAGE = "login";

    /**
     * Creates an object
     *
     * @param  \SimpleXMLElement $xml     Contents of security.authorization.by_dao tag @ configuration.xml
     * @param  Request           $request Encapsulated request made by client
     * @param  int|string|null   $userID  Unique user identifier (usually an int)
     * @throws ConfigurationException If resources referenced in XML do not exist or do not extend/implement blueprint.
     */
    public function __construct(\SimpleXMLElement $xml, Request $request, int|string|null $userID)
    {
        // create dao object
        $xmlTag = $xml->authorization->by_dao;

        // detects logged in callback to use if authorization fails
        $loggedInCallback = (string) $xmlTag["logged_in_callback"];
        if (!$loggedInCallback) {
            $loggedInCallback = self::DEFAULT_LOGGED_IN_PAGE;
        }

        // detects logged out callback to use if authorization fails
        $loggedOutCallback = (string) $xmlTag["logged_out_callback"];
        if (!$loggedOutCallback) {
            $loggedOutCallback = self::DEFAULT_LOGGED_OUT_PAGE;
        }

        // loads and instances page DAO object
        $pageDAO = $this->getPageDAO($xml, $request->getUri());

        // loads and instances user DAO object
        $userDAO = $this->getUserDAO($xml, $userID);

        // performs authorization
        $authorization = new Authorization($loggedInCallback, $loggedOutCallback);
        $this->setResult($authorization->authorize($pageDAO, $userDAO, $request->getMethod()));
    }

    /**
     * Gets DAO where page rights are checked
     *
     * @param  \SimpleXMLElement $xml
     * @param  string            $pageUrl
     * @return PageAuthorizationDAO
     * @throws ConfigurationException
     */
    private function getPageDAO(\SimpleXMLElement $xml, string $pageUrl): PageAuthorizationDAO
    {
        $className = (string) $xml->authorization->by_dao["page_dao"];
        if (!$className) {
            throw new ConfigurationException("Attribute 'page_dao' is mandatory for 'by_dao' tag");
        }
        return new $className($pageUrl);
    }

    /**
     * Gets DAO where user rights are checked
     *
     * @param  \SimpleXMLElement $xml
     * @param  int|string|null   $userID
     * @return UserAuthorizationDAO
     * @throws ConfigurationException
     */
    private function getUserDAO(\SimpleXMLElement $xml, int|string|null $userID): UserAuthorizationDAO
    {
        $className = (string) $xml->authorization->by_dao["user_dao"];
        if (!$className) {
            throw new ConfigurationException("Attribute 'user_dao' is mandatory for 'by_dao' tag");
        }
        return new $className($userID);
    }
}
