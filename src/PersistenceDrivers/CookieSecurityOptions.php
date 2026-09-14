<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

/**
 * Carries cookie security attributes and lifetime settings for persistence drivers
 *
 * Defaults to HttpOnly and Secure disabled, SameSite Lax, and a zero duration.
 * The duration is interpreted by each driver: sessions use it for cookie
 * lifetime and idle expiration, while remember-me uses it for cookie and
 * token expiration. Zero is not a universal unlimited-lifetime setting.
 *
 * @see CookieSameSiteOptions
 * @see Session\PersistenceDriver
 * @see RememberMe\PersistenceDriver
 */
final class CookieSecurityOptions
{
    private bool $isHttpOnly = false;
    private bool $isSecure = false;
    private CookieSameSiteOptions $sameSite = CookieSameSiteOptions::LAX;
    private int $expirationTime = 0;

    /**
     * Sets the lifetime or idle timeout used by the persistence driver
     *
     * @param int $expirationTime Duration in seconds, interpreted by the consuming driver
     */
    public function setExpirationTime(int $expirationTime): void
    {
        $this->expirationTime = $expirationTime;
    }

    /**
     * Gets the lifetime or idle timeout used by the persistence driver
     *
     * @return int Duration in seconds; defaults to zero
     */
    public function getExpirationTime(): int
    {
        return $this->expirationTime;
    }

    /**
     * Sets whether the cookie should carry the HttpOnly attribute
     *
     * @param bool $isHttpOnly Whether browser script access to the cookie should be restricted
     */
    public function setIsHttpOnly(bool $isHttpOnly): void
    {
        $this->isHttpOnly = $isHttpOnly;
    }

    /**
     * Gets whether the cookie should carry the HttpOnly attribute
     *
     * @return bool True when HttpOnly is enabled; defaults to false
     */
    public function isHttpOnly(): bool
    {
        return $this->isHttpOnly;
    }

    /**
     * Sets whether the cookie should carry the Secure attribute
     *
     * @param bool $isSecure Whether the cookie should be restricted to secure transport
     */
    public function setIsSecure(bool $isSecure): void
    {
        $this->isSecure = $isSecure;
    }

    /**
     * Gets whether the cookie should carry the Secure attribute
     *
     * @return bool True when Secure is enabled; defaults to false
     */
    public function isSecure(): bool
    {
        return $this->isSecure;
    }

    /**
     * Sets the cookie SameSite policy
     *
     * @param CookieSameSiteOptions $sameSite SameSite policy to apply
     */
    public function setSameSite(CookieSameSiteOptions $sameSite): void
    {
        $this->sameSite = $sameSite;
    }

    /**
     * Gets the cookie SameSite policy
     *
     * @return CookieSameSiteOptions Selected policy; defaults to LAX
     */
    public function getSameSite(): CookieSameSiteOptions
    {
        return $this->sameSite;
    }
}
