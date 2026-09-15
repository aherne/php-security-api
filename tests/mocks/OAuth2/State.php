<?php

namespace Test\Lucinda\WebSecurity\mocks\OAuth2;

use Lucinda\WebSecurity\OAuth2State;

final class State implements OAuth2State
{
    public bool $accepted = true;
    public ?string $savedState = null;
    public ?string $savedVendor = null;
    public ?int $validUntil = null;

    public function save(string $state, string $vendorName, int $validUntil): void
    {
        $this->savedState = $state;
        $this->savedVendor = $vendorName;
        $this->validUntil = $validUntil;
    }

    public function consume(string $state, string $vendorName): bool
    {
        return $this->accepted;
    }
}
