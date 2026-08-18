<?php
namespace Test\Lucinda\WebSecurity\mocks\Authentication;

use Lucinda\WebSecurity\DAO\MultiFactorAuthentication;

class MockMultiFactorAuthentication implements MultiFactorAuthentication
{
    /** @var array<int|string,int> */
    private static array $consumedCounters = [];

    public function isRequired(int|string $userID): bool
    {
        return true;
    }

    public function getAccountName(int|string $userID): string
    {
        return "user";
    }

    public function getSecret(int|string $userID): ?string
    {
        return null;
    }

    public function getSetupSecret(int|string $userID): ?string
    {
        return null;
    }

    public function saveSetupSecret(int|string $userID, string $secret): void
    {
    }

    public function enable(int|string $userID, string $secret): void
    {
    }

    public function clearSetupSecret(int|string $userID): void
    {
    }

    public function consumeTotpCounter(int|string $userID, int $counter): bool
    {
        $lastCounter = self::$consumedCounters[$userID] ?? null;
        if ($lastCounter !== null && $counter <= $lastCounter) {
            return false;
        }

        self::$consumedCounters[$userID] = $counter;
        return true;
    }

    public function penalize(int|string $userID): void
    {
    }

    public function isThrottled(int|string $userID): bool
    {
        return false;
    }
}
