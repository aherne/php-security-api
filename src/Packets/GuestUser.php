<?php

namespace Lucinda\WebSecurity\Packets;

final class GuestUser extends Packet
{
    private string $csrfToken;

    public function __construct(string $csrfToken)
    {
        $this->csrfToken = $csrfToken;
    }

    public function getCsrfToken(): string
    {
        return $this->csrfToken;
    }
}