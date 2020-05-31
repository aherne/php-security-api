<?php
namespace Lucinda\WebSecurity\Authentication\OAuth2;

/**
 * Encapsulates abstract information about remote logged in user on OAuth2 provider.
 */
interface UserInformation
{
    /**
     * Gets remote user id.
     *
     * @return integer|string
     */
    public function getId();
    
    /**
     * Gets remote user name.
     *
     * @return string
     */
    public function getName(): string;
    
    /**
     * Gets remote user email.
     *
     * @return string
     */
    public function getEmail(): string;
}
