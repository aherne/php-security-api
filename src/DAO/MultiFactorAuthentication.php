<?php

namespace Lucinda\WebSecurity\DAO;

interface MultiFactorAuthentication
{
    public function isRequired(int|string $userID): bool;
    public function getAccountName(int|string $userID): string;
    public function getSecret(int|string $userID): ?string;
    public function getSetupSecret(int|string $userID): ?string;
    public function saveSetupSecret(int|string $userID, string $secret): void;
    public function enable(int|string $userID, string $secret): void;
    public function clearSetupSecret(int|string $userID): void;
    public function penalize(int|string $userID): void;
    public function isThrottled(int|string $userID): bool;
}
