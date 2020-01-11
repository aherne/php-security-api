<?php
namespace Lucinda\WebSecurity\Authentication\OAuth2;

/**
 * Detects oauth2 information based on contents of <oauth2> XML tag
 */
class XMLParser
{
    const DEFAULT_LOGIN_PAGE = "login";
    const DEFAULT_LOGOUT_PAGE = "logout";
    const DEFAULT_TARGET_PAGE = "index";
    
    private $loginCallback;
    private $logoutCallback;
    private $targetCallback;
    
    /**
     * Kick-starts detection process.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setLoginCallback($xml);
        $this->setLogoutCallback($xml);
        $this->setTargetCallback($xml);
    }
    
    /**
     * Sets callback URL to use in login failures
     *
     * @param \SimpleXMLElement $xml Pointer to <security> tag.
     */
    private function setLoginCallback($xml)
    {
        $loginPage = (string) $xml->authentication->oauth2["login"];
        if (!$loginPage) {
            $loginPage = self::DEFAULT_LOGIN_PAGE;
        }
        $this->loginCallback = $loginPage;
    }
    
    /**
     * Sets callback URL to use in user logout
     *
     * @param \SimpleXMLElement $xml Pointer to <security> tag.
     */
    private function setLogoutCallback($xml)
    {
        $logoutPage = (string) $xml->authentication->oauth2["logout"];
        if (!$logoutPage) {
            $logoutPage = self::DEFAULT_LOGOUT_PAGE;
        }
        $this->logoutCallback = $logoutPage;
    }
    
    /**
     * Sets callback URL to use in login successes
     *
     * @param \SimpleXMLElement $xml Pointer to <security> tag.
     */
    private function setTargetCallback($xml)
    {
        $targetPage = (string) $xml->authentication->oauth2["target"];
        if (!$targetPage) {
            $targetPage = self::DEFAULT_TARGET_PAGE;
        }
        $this->targetCallback = $targetPage;
    }
    
    /**
     * Gets callback URL to use in login failures
     *
     * @return string
     */
    public function getLoginCallback()
    {
        return $this->loginCallback;
    }
    
    /**
     * Gets callback URL to use in user logout
     *
     * @return string
     */
    public function getLogoutCallback()
    {
        return $this->logoutCallback;
    }
    
    /**
     * Gets callback URL to use in login successes
     *
     * @return string
     */
    public function getTargetCallback()
    {
        return $this->targetCallback;
    }
}
