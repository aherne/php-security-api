<?php

namespace Test\Lucinda\WebSecurity\mocks\Authentication;

use Lucinda\WebSecurity\DAO\LoginThrottler;

class MockLoginThrottler implements LoginThrottler
{
    private array $attempts = [];

    public function penalize(string $userName, string $ipAddress): void
    {
        $key = $userName."@".$ipAddress;
        $this->attempts[$key] = ($this->attempts[$key] ?? 0) + 1;
    }

    public function isStopped(string $userName, string $ipAddress): bool
    {
        return ($this->attempts[$userName."@".$ipAddress] ?? 0) >= 3;
    }
}
