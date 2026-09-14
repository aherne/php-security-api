<?php

namespace Lucinda\WebSecurity\Security\Authorization;

/**
 * Shares computed-result storage for authorization implementations
 *
 * Concrete implementations must assign a result before exposing it through
 * getResult(). Reading the result does not perform another access check.
 *
 * @internal
 * @see Result
 */
class Generic
{
    private Result $result;

    /**
     * Stores the result computed by a concrete authorization implementation
     *
     * @param Result $result Authorization decision and associated failure callback
     */
    protected function setResult(Result $result): void
    {
        $this->result = $result;
    }

    /**
     * Gets the previously assigned authorization result
     *
     * @return Result Decision stored by the concrete implementation
     */
    public function getResult(): Result
    {
        return $this->result;
    }
}