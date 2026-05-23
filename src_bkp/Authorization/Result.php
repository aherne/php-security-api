<?php

namespace Lucinda\WebSecurity\Authorization;

/**
 * Encapsulates request authorization results.
 */
class Result
{
    private ResultStatus $status;
    private string $callbackURI;

    /**
     * Saves authorization result encapsulated by ResultStatus enum along with callback URI
     *
     * @param ResultStatus $status
     * @param string       $callbackURI
     */
    public function __construct(ResultStatus $status, string $callbackURI)
    {
        $this->status = $status;
        $this->callbackURI = $callbackURI;
    }

    /**
     * Gets authorization status.
     *
     * @return ResultStatus
     */
    public function getStatus(): ResultStatus
    {
        return $this->status;
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
}
