<?php

namespace Test\Lucinda\WebSecurity\mocks\Authentication;

use Lucinda\WebSecurity\DAO\Throttler\FormLogin;

final class FormLoginThrottler implements FormLogin
{
    public static bool $throttled = false;
    public static int $penalties = 0;

    public function penalize(string $userName, string $ipAddress): void
    {
        self::$penalties++;
    }

    public function isThrottled(string $userName, string $ipAddress): bool
    {
        return self::$throttled;
    }

    public static function reset(): void
    {
        self::$throttled = false;
        self::$penalties = 0;
    }
}
