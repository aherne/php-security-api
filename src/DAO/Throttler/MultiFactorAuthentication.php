<?php

namespace Lucinda\WebSecurity\DAO\Throttler;

/**
 * Defines the DAO contract for throttling failed multi-factor authentication attempts
 *
 * Register the implementation class through the 'throttler' attribute
 * of security > multi_factor_authentication.
 *
 * @see \Lucinda\WebSecurity\Configuration\MultiFactorAuthentication
 */
interface MultiFactorAuthentication
{
    /**
     * Records a failed MFA setup or challenge attempt for a local user and client IP
     *
     * @param int|string $userID Non-empty local user ID
     * @param string $ipAddress Client IP address
     */
    public function penalize(int|string $userID, string $ipAddress): void;
    
    /**
     * Checks whether the current throttling policy blocks this user's MFA attempt
     *
     * @param int|string $userID Non-empty local user ID
     * @param string $ipAddress Client IP address
     * @return bool True when MFA is blocked; false when the attempt may proceed
     */
    public function isThrottled(int|string $userID, string $ipAddress): bool;
}