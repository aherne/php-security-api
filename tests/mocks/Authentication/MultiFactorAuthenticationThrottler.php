<?php

namespace Test\Lucinda\WebSecurity\mocks\Authentication;

use Lucinda\WebSecurity\DAO\Throttler\MultiFactorAuthentication;

final class MultiFactorAuthenticationThrottler implements MultiFactorAuthentication
{
    public static bool $throttled = false;
    public static int $penalties = 0;

    public function penalize(int|string $userID, string $ipAddress): void
    {
        self::$penalties++;
    }

    public function isThrottled(int|string $userID, string $ipAddress): bool
    {
        return self::$throttled;
    }

    public static function reset(): void
    {
        self::$throttled = false;
        self::$penalties = 0;
    }
}
