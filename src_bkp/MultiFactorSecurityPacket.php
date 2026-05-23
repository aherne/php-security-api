<?php

namespace Lucinda\WebSecurity;

class MultiFactorSecurityPacket extends SecurityPacket
{
    private int|string $userID;

    public function setUserID(int|string $userID): void
    {
        $this->userID = $userID;
    }

    public function getUserID(): int|string
    {
        return $this->userID;
    }
}