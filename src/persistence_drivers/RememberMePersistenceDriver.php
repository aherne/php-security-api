<?php
namespace Lucinda\WebSecurity;

require_once("PersistenceDriver.php");
require_once(dirname(__DIR__)."/token/SynchronizerToken.php");

/**
 * Encapsulates a driver that persists unique user identifier into a crypted "remember me" cookie variable.
 */
class RememberMePersistenceDriver implements PersistenceDriver
{
    private $token;
    
    private $parameterName;
    private $expirationTime;
    private $isHttpOnly;
    private $isSecure;
    
    /**
     * Creates a persistence driver object.
     *
     * @param string $secret Strong password to use for crypting. (Check: http://randomkeygen.com/)
     * @param string $parameterName Name of SESSION parameter that holds cypted unique user identifier.
     * @param number $expirationTime Time by which cookie expires (cannot be renewed), in seconds.
     * @param string $isHttpOnly  Whether or not cookie should be using HTTP-only.
     * @param string $isSecure Whether or not cookie should be using HTTPS-only.
     * @param string $ip Value of REMOTE_ADDR attribute, unless ignored.
     */
    public function __construct($secret, $parameterName, $expirationTime, $isHttpOnly = false, $isSecure = false, $ip="")
    {
        $this->token = new SynchronizerToken($ip, $secret);
        $this->parameterName = $parameterName;
        $this->expirationTime = $expirationTime;
        $this->isHttpOnly = $isHttpOnly;
        $this->isSecure = $isSecure;
    }

    /**
     * {@inheritDoc}
     * @see PersistenceDriver::load()
     */
    public function load()
    {
        if (empty($_COOKIE[$this->parameterName])) {
            return;
        }
        
        try {
            return $this->token->decode($_COOKIE[$this->parameterName]);
        } catch (\Exception $e) {
            // delete bad cookie
            setcookie($this->parameterName, "", 1);
            setcookie($this->parameterName, false);
            unset($_COOKIE[$this->parameterName]);
            // rethrow exception, unless it's token expired
            if ($e instanceof TokenExpiredException) {
                return;
            } else {
                throw $e;
            }
        }
    }

    /**
     * {@inheritDoc}
     * @see PersistenceDriver::save()
     */
    public function save($userID)
    {
        $token = $this->token->encode($userID, $this->expirationTime);
        setcookie($this->parameterName, $token, time()+$this->expirationTime, "", "", $this->isSecure, $this->isHttpOnly);
        $_COOKIE[$this->parameterName] = $token;
    }
    
    /**
     * {@inheritDoc}
     * @see PersistenceDriver::clear()
     */
    public function clear()
    {
        setcookie($this->parameterName, "", 1);
        setcookie($this->parameterName, false);
        unset($_COOKIE[$this->parameterName]);
    }
}
