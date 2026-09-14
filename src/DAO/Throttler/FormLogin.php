<?php

namespace Lucinda\WebSecurity\DAO\Throttler;

/**
 * Defines the DAO contract for throttling failed form login attempts
 *
 * Register the implementation class through the 'throttler' attribute
 * of security > authentication > form.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authentication\Form
 */
interface FormLogin
{
    /**
     * Records a rejected credential attempt for the supplied username and client IP
     *
     * @param string $userName Submitted username, which may not identify an existing account
     * @param string $ipAddress Client IP address
     */
    function penalize(string $userName, string $ipAddress): void;

    /**
     * Checks whether the current throttling policy blocks this login attempt
     *
     * @param string $userName Submitted username
     * @param string $ipAddress Client IP address
     * @return bool True when login is blocked; false when the attempt may proceed
     */
    function isThrottled(string $userName, string $ipAddress): bool;
}
