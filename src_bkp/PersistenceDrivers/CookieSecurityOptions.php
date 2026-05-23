<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

/**
 * Configures cookies security and duration
 */
class CookieSecurityOptions
{
    private bool $isHttpOnly = false;
    private bool $isSecure = false;
    private CookieSameSiteOptions $sameSite = CookieSameSiteOptions::LAX;
    private int $expirationTime = 0;

    /**
     * Sets elapsed time by which cookie expires
     *
     * @param int $expirationTime
     */
    public function setExpirationTime(int $expirationTime): void
    {
        $this->expirationTime = $expirationTime;
    }

    /**
     * Gets elapsed time by which cookie expires
     *
     * @return int
     */
    public function getExpirationTime(): int
    {
        return $this->expirationTime;
    }

    /**
     * Sets if cookie is httponly
     *
     * @param bool $isHttpOnly
     */
    public function setIsHttpOnly(bool $isHttpOnly): void
    {
        $this->isHttpOnly = $isHttpOnly;
    }

    /**
     * Gets if cookie is httponly
     *
     * @return bool
     */
    public function isHttpOnly(): bool
    {
        return $this->isHttpOnly;
    }

    /**
     * Sets if cookie is only accessible on HTTPS connections
     *
     * @param bool $isSecure
     */
    public function setIsSecure(bool $isSecure): void
    {
        $this->isSecure = $isSecure;
    }

    /**
     * Gets if cookie is only accessible on HTTPS connections
     *
     * @return bool
     */
    public function isSecure(): bool
    {
        return $this->isSecure;
    }

    /**
     * Sets if cookie SameSite options
     *
     * @param CookieSameSiteOptions $sameSite
     */
    public function setSameSite(CookieSameSiteOptions $sameSite): void
    {
        $this->sameSite = $sameSite;
    }

    /**
     * Gets if cookie is restricted with SameSite flag
     *
     * @return CookieSameSiteOptions
     */
    public function getSameSite(): CookieSameSiteOptions
    {
        return $this->sameSite;
    }
}
