<?php

namespace Lucinda\WebSecurity\Authorization\XML;

use Lucinda\WebSecurity\Authorization\UserRoles;
use Lucinda\WebSecurity\ConfigurationException;

/**
 * Encapsulates users authorization via <users> XML tag
 */
class UserAuthorizationXML implements UserRoles
{
    private \SimpleXMLElement $xml;

    /**
     * Sets XML to authorize into
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->xml = $xml;
    }

    /**
     * Gets user roles from XML
     *
     * @param  int|string|null $userID
     * @throws ConfigurationException
     * @return string[]
     */
    public function getRoles(int|string|null $userID): array
    {
        // gets default roles
        $defaultRoles = [];
        if (empty($this->xml->users['roles'])) {
            throw new ConfigurationException("XML tag users requires attribute: roles");
        }
        $tmp = (string) $this->xml->users["roles"];
        $tmp= explode(",", $tmp);
        foreach ($tmp as $role) {
            $defaultRoles[] = trim($role);
        }

        // gets user roles
        $detector = new RolesDetector($this->xml, "users", "user", "id", $userID);
        $userRoles = $detector->getRoles();

        return (!empty($userRoles) ? $userRoles : $defaultRoles);
    }
}
