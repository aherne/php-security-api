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
     */
    public function penalize(int|string $userID): void;
    /**
     * Checks whether multi-factor authentication is throttled.
     *
     * @param int|string $userID
     * @return bool
     */
    public function isThrottled(int|string $userID): bool;
}