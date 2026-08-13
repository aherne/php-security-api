<?php

namespace Lucinda\WebSecurity\DAO\Throttler;

/**
 * Guards multi-factor authentication against brute-force attacks
 */
interface MultiFactorAuthentication
{
    /**
     * Records a failed multi-factor attempt.
     *
     * @param int|string $userID
     * @param string $ipAddress
     */
    public function penalize(int|string $userID, string $ipAddress): void;
    
    /**
     * Checks whether multi-factor authentication is throttled.
     *
     * @param int|string $userID
     * @param string $ipAddress
     * @return bool
     */
    public function isThrottled(int|string $userID, string $ipAddress): bool;
}