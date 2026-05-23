<?php

namespace Lucinda\WebSecurity\Authentication\XML;

use Lucinda\WebSecurity\ConfigurationException;

/**
 * Encapsulates authentication via <users> XML tag
 */
class UserAuthenticationXML
{
    private \SimpleXMLElement $xml;

    /**
     * Sets XML to authorize user into.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->xml = $xml;
    }

    /**
     * Authenticates user by username and password.
     *
     * @param  string $username
     * @param  string $password
     * @throws ConfigurationException
     * @return string|null
     */
    public function login(string $username, string $password): string|null
    {
        $userID = null;

        // extract user id
        if (!$this->xml->users) {
            throw new ConfigurationException("XML tag users not defined!");
        }
        $info = $this->xml->xpath("//users/user[@username='".$username."']");
        if (!empty($info[0])) {
            $currentPassword = (string) $info[0]['password'];
            if (!$currentPassword) {
                throw new ConfigurationException("Attribute 'password' is mandatory for 'user' tag");
            }
            if (password_verify($password, $currentPassword)) {
                $userID = (string) $info[0]["id"];
                if (!$userID) {
                    throw new ConfigurationException("Attribute 'id' is mandatory for 'user' tag");
                }
            }
        }

        return $userID;
    }
}
