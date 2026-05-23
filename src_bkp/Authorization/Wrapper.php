<?php

namespace Lucinda\WebSecurity\Authorization;

/**
 * Defines an abstract authorization mechanism that works with AuthenticationResult
 */
abstract class Wrapper
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
