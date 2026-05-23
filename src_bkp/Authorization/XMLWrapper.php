<?php

namespace Lucinda\WebSecurity\Authorization;

use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Authorization\XML\Authorization;
use Lucinda\WebSecurity\Authorization\XML\UserAuthorizationXML;
use Lucinda\WebSecurity\ConfigurationException;

/**
 * Binds XMLAuthorization @ SECURITY-API to settings from configuration.xml @ SERVLETS-API then performs request
 * authorization via contents of configuration.xml.
 */
class XMLWrapper extends Wrapper
{
    public const DEFAULT_LOGGED_IN_PAGE = "index";
    public const DEFAULT_LOGGED_OUT_PAGE = "login";

    /**
     * Creates an object.
     *
     * @param \SimpleXMLElement $xml     Contents of root @ configuration.xml
     * @param Request           $request Encapsulated request made by client
     * @param int|string|null   $userID  Unique user identifier
     */
    public function __construct(\SimpleXMLElement $xml, Request $request, int|string|null $userID)
    {
        // move up in xml tree
        $xmlLocal = $xml->authorization->by_xml;

        $loggedInCallback = (string) $xmlLocal["logged_in_callback"];
        if (!$loggedInCallback) {
            $loggedInCallback = self::DEFAULT_LOGGED_IN_PAGE;
        }

        $loggedOutCallback = (string) $xmlLocal["logged_out_callback"];
        if (!$loggedOutCallback) {
            $loggedOutCallback = self::DEFAULT_LOGGED_OUT_PAGE;
        }

        // authorize and save result
        $authorization = new Authorization($loggedInCallback, $loggedOutCallback);
        $this->setResult(
            $authorization->authorize(
                $xml->xpath("..")[0],
                $request->getUri(),
                $userID,
                $this->getDAO($xml, $userID)
            )
        );
    }

    /**
     * Gets algorithm to check if page roles match that of current user
     *
     * @param  \SimpleXMLElement $xml
     * @param  int|string|null   $userID
     * @return UserRoles
     */
    private function getDAO(\SimpleXMLElement $xml, int|string|null $userID): UserRoles
    {
        $daoClass = "";
        if ($tag = $xml->authentication->form) {
            $daoClass = (string) $tag["dao"];
        } elseif ($tag = $xml->authentication->oauth2) {
            $daoClass = (string) $tag["dao"];
        }
        if ($daoClass) {
            return new $daoClass($userID);
        } else {
            return new UserAuthorizationXML($xml->xpath("..")[0]);
        }
    }
}
