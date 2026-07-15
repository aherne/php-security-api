<?php
namespace Test\Lucinda\WebSecurity\mocks\Authentication;

use Lucinda\WebSecurity\DAO\MultiFactorAuthentication;

class MockMultiFactorAuthentication implements MultiFactorAuthentication
{

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

    public function penalize(int|string $userID): void
    {
    }

    public function isThrottled(int|string $userID): bool
    {
        return false;
    }
}
