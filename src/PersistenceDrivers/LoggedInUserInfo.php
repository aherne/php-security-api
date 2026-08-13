<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

final class LoggedInUserInfo
{
    private int|string $userID;
    private AuthenticationStage $stage;
    private ?int $stageValidUntil = null;
    private bool $rememberRequested = false;

    public function __construct(
        int|string $userID,
        AuthenticationStage $stage,
        bool $rememberRequested = false,
        ?int $stageValidUntil = null
    ) {
        $this->userID = $userID;
        $this->stage = $stage;
        $this->rememberRequested = $rememberRequested;
        $this->stageValidUntil = $stageValidUntil;
    }

    public function getUserID(): int|string
    {
        return $this->userID;
    }

    public function getAuthenticatedStage(): AuthenticationStage
    {
        return $this->stage;
    }

    public function getStageValidUntil(): ?int
    {
        return $this->stageValidUntil;
    }

    public function rememberRequested(): bool
    {
        return $this->rememberRequested;
    }
}