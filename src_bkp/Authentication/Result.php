<?php

namespace Lucinda\WebSecurity\Authentication;

use Lucinda\WebSecurity\Authentication\MultiFactor\ResultStatus as MultiFactorResultStatus;

/**
 * Encapsulates authentication response
 */
class Result
{
    private ResultStatus|MultiFactorResultStatus $status;
    private string $callbackURI;
    private string|int|null $userID = null;
    private int $timePenalty = 0;

    /**
     * Saves authentication result encapsulated by ResultStatus enum
     *
     * @param ResultStatus|MultiFactorResultStatus $status
     */
    public function __construct(ResultStatus|MultiFactorResultStatus $status)
    {
        $this->status = $status;
    }

    /**
     * Gets authentication status.
     *
     * @return ResultStatus|MultiFactorResultStatus
     */
    public function getStatus(): ResultStatus|MultiFactorResultStatus
    {
        return $this->status;
    }

    /**
     * Sets callback URL.
     *
     * @param string $callbackURI
     */
    public function setCallbackURI(string $callbackURI): void
    {
        $this->callbackURI = $callbackURI;
    }

    /**
     * Gets callback URI
     *
     * @return string
     */
    public function getCallbackURI(): string
    {
        return $this->callbackURI;
    }

    /**
     * Sets user unique identifier
     *
     * @param string|int $userID
     */
    public function setUserID(string|int $userID): void
    {
        $this->userID = $userID;
    }

    /**
     * Gets user unique identifier.
     *
     * @return string|int|null
     */
    public function getUserID(): string|int|null
    {
        return $this->userID;
    }

    /**
     * Sets number of seconds client will be banned from authenticating
     *
     * @param int $timePenalty
     */
    public function setTimePenalty(int $timePenalty): void
    {
        $this->timePenalty = $timePenalty;
    }

    /**
     * Gets number of seconds client will be banned from authenticating
     *
     * @return int
     */
    public function getTimePenalty(): int
    {
        return $this->timePenalty;
    }
}
