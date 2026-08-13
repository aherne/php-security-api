<?php

namespace Lucinda\WebSecurity\DAO\Throttler;

/**
 * Guards form login against brute-force attacks
 */
interface FormLogin
{
    /**
     * Records a failed form login attempt.
     *
     * @param string $userName
     * @param string $ipAddress
     */
    function penalize(string $userName, string $ipAddress): void;

    /**
     * Checks if username is already throttled
     *
     * @param string $userName
     * @param string $ipAddress
     * @return bool
     */
    function isThrottled(string $userName, string $ipAddress): bool;
}
