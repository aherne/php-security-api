<?php

namespace Lucinda\WebSecurity\Authentication\Form;

/**
 * Encapsulates login request data
 */
class LoginRequest extends UrlTargetRequest
{
    private string $username;
    private string $password;
    private bool $rememberMe;

    /**
     * Sets value of user name sent in login attempt.
     *
     * @param string $username
     */
    public function setUsername(string $username): void
    {
        $this->username = $username;
    }

    /**
     * Sets value of user password sent in login attempt.
     *
     * @param string $password
     */
    public function setPassword(string $password): void
    {
        $this->password= $password;
    }

    /**
     * Sets value of remember me option sent in login attempt (or null, if application doesn't support remember me)
     *
     * @param bool $rememberMe
     */
    public function setRememberMe(bool $rememberMe): void
    {
        $this->rememberMe= $rememberMe;
    }

    /**
     * Gets value of user name sent in login attempt.
     *
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * Gets value of user password sent in login attempt.
     *
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    /**
     * Gets value of remember me option sent in login attempt (or null, if application doesn't support remember me)
     *
     * @return boolean
     */
    public function isRememberMe(): bool
    {
        return $this->rememberMe;
    }

    /**
     * Gets default login source page, if none set in XML
     *
     * @return string
     */
    protected function getDefaultSourcePage(): string
    {
        return "login";
    }

    /**
     * Gets default login target page, if none set in XML
     *
     * @return string
     */
    protected function getDefaultDestinationPage(): string
    {
        return "index";
    }
}
