<?php

namespace Test\Lucinda\WebSecurity\mocks\Authentication;

use Lucinda\WebSecurity\DAO\MultiFactorAuthentication;

final class MultiFactorAuthenticationDAO implements MultiFactorAuthentication
{
    public static bool $required = true;
    public static ?string $secret = "JBSWY3DPEHPK3PXP";
    public static ?string $setupSecret = null;
    public static ?int $consumedCounter = null;

    public function isRequired(int|string $userID): bool
    {
        return self::$required;
    }

    public function getAccountName(int|string $userID): string
    {
        return "user-".$userID;
    }

    public function getSecret(int|string $userID): ?string
    {
        return self::$secret;
    }

    public function getSetupSecret(int|string $userID): ?string
    {
        return self::$setupSecret;
    }

    public function saveSetupSecret(int|string $userID, string $secret): void
    {
        self::$setupSecret = $secret;
    }

    public function enable(int|string $userID, string $secret): void
    {
        self::$secret = $secret;
        self::$setupSecret = null;
    }

    public function clearSetupSecret(int|string $userID): void
    {
        self::$setupSecret = null;
    }

    public function consumeTotpCounter(int|string $userID, int $counter): bool
    {
        if (self::$consumedCounter === $counter) {
            return false;
        }
        self::$consumedCounter = $counter;

        return true;
    }

    public static function reset(): void
    {
        self::$required = true;
        self::$secret = "JBSWY3DPEHPK3PXP";
        self::$setupSecret = null;
        self::$consumedCounter = null;
    }
}
