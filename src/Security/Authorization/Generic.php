<?php

namespace Lucinda\WebSecurity\Security\Authorization;

/**
 * Encapsulates Generic logic.
 */
class Generic
{
    private Result $result;

    /**
     * Sets result of authorization attempt.
     *
     * @param Result $result
     */
    protected function setResult(Result $result): void
    {
        $this->result = $result;
    }

    /**
     * Gets result of authorization attempt
     *
     * @return Result
     */
    public function getResult(): Result
    {
        return $this->result;
    }
}