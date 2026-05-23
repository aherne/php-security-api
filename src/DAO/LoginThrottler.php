<?php

namespace Lucinda\WebSecurity\DAO;

/**
 * Performs login/logout via database if path requested matches paths @ xml
 */
interface LoginThrottler
{
    function penalize(string $userName, string $ipAddress): void;
    function isStopped(string $userName, string $ipAddress): bool;
}
