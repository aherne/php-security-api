<?php

namespace Lucinda\WebSecurity\DAO\Throttler;

/**
 * Guards form login against brute-force attacks
 */
interface FormLogin
{
    function penalize(string $userName, string $ipAddress): void;
    function isThrottled(string $userName, string $ipAddress): bool;
}
