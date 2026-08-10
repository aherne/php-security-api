<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

final class LoggedInUserInfo
{
    private int|string $userID;
    private AuthenticationStage $stage;
    private ?int $mfaValidUntil = null;
    private bool $rememberRequested = false;

    public function __construct(
        int|string $userID,
        AuthenticationStage $stage,
        bool $rememberRequested = false,
        ?int $mfaValidUntil = null
    ) {
        $this->userID = $userID;
        $this->stage = $stage;
        $this->rememberRequested = $rememberRequested;
        $this->mfaValidUntil = $mfaValidUntil;
    }

    public function getUserID(): int|string
    {
        return $this->userID;
    }

    public function getAuthenticatedStage(): AuthenticationStage
    {
        return $this->stage;
    }

    public function getMfaValidUntil(): ?int
    {
        return $this->mfaValidUntil;
    }

    public function rememberRequested(): bool
    {
        return $this->rememberRequested;
    }
}