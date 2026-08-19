<?php

namespace Lucinda\WebSecurity;

interface OAuth2State
{
    /**
     * Saves a state for one provider and login attempt.
     */
    public function save(
        string $state,
        string $vendorName,
        int $validUntil
    ): void;

    /**
     * Atomically validates and removes the state.
     */
    public function consume(
        string $state,
        string $vendorName
    ): bool;
}
