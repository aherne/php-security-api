<?php

namespace Test\Lucinda\WebSecurity\mocks;

use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver as PersistenceDriverInterface;

final class PersistenceDriver implements PersistenceDriverInterface
{
    public ?LoggedInUserInfo $stored = null;
    public int $saves = 0;
    public int $clears = 0;

    public function load(): ?LoggedInUserInfo
    {
        return $this->stored;
    }

    public function save(LoggedInUserInfo $authentication): void
    {
        $this->stored = $authentication;
        $this->saves++;
    }

    public function clear(): void
    {
        $this->stored = null;
        $this->clears++;
    }
}
