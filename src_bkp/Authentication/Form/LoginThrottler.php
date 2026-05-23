<?php

namespace Lucinda\WebSecurity\Authentication\Form;

use Lucinda\WebSecurity\Request;

/**
 * Defines blueprints of a login throttler, able to guard against BruteForce login attempts
 */
abstract class LoginThrottler
{
    protected Request $request;
    protected string $userName;

    /**
     * Detects client throttling state based on arguments provided.
     *
     * @param Request $request  Encapsulated client request data.
     * @param string  $userName Username client has attempted
     */
    public function __construct(Request $request, string $userName)
    {
        $this->request = $request;
        $this->userName = $userName;

        $this->setCurrentStatus();
    }

    /**
     * Sets current throttling status based on arguments provided
     */
    abstract protected function setCurrentStatus(): void;

    /**
     * Gets number of seconds client will be banned from authenticating
     *
     * @return int
     */
    abstract public function getTimePenalty(): int;

    /**
     * Marks subsequent login as failed, making client liable for time penalties
     */
    abstract public function setFailure(): void;

    /**
     * Marks subsequent login as successful, removing any previous failures and penalties
     */
    abstract public function setSuccess(): void;
}
