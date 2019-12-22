<?php
namespace Lucinda\WebSecurity\Authentication\XML;

use Lucinda\WebSecurity\Authentication\Exception;

/**
 * Encapsulates authentication via <users> XML tag
 */
class UserAuthenticationXML
{
    private $xml;
    
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
     * @param string $username
     * @param string $password
     * @throws Exception
     * @return string
     */
    public function login(string $username, string $password): string
    {
        $userID = null;
        
        // extract user id
        $tmp = (array) $this->xml->users;
        if (empty($tmp)) {
            throw new Exception("XML tag users not defined!");
        }
        $tmp = $tmp["user"];
        if (!is_array($tmp)) {
            $tmp = array($tmp);
        }
        foreach ($tmp as $info) {
            $currentUserName = (string) $info['username'];
            $currentPassword = (string) $info['password'];
            if (!$currentUserName || !$currentPassword) {
                throw new Exception("XML tag users > user requires parameters: username, password");
            }
            if ($username == $currentUserName && password_verify($password, $currentPassword)) {
                $userID = (string) $info["id"];
                if (!$userID) {
                    throw new Exception("XML tag users / user requires parameter: id");
                }
            }
        }
        
        return $userID;
    }
}
