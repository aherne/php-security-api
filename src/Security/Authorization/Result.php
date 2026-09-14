<?php

namespace Lucinda\WebSecurity\Security\Authorization;

/**
 * Carries an authorization decision and its optional failure route
 *
 * Authorization implementations produce this result for the enclosing
 * wrapper. The wrapper turns denied access into a security packet and
 * prefixes a non-empty callback route with the application context.
 *
 * @see ResultStatus
 * @see \Lucinda\WebSecurity\Wrapper\Authorization
 */
class Result
{
    private ResultStatus $status;
    private string $callbackURI;

    /**
     * Stores an authorization decision and its callback route
     *
     * @param ResultStatus $status Resource-access decision
     * @param string $callbackURI Configured failure route, or an empty string when no callback is needed
     */
    public function __construct(ResultStatus $status, string $callbackURI)
    {
        $this->status = $status;
        $this->callbackURI = $callbackURI;
    }

    /**
     * Gets the resource-access decision
     *
     * @return ResultStatus Computed authorization decision
     */
    public function getStatus(): ResultStatus
    {
        return $this->status;
    }

    /**
     * Gets the configured failure route without performing a redirect
     *
     * @return string Failure route before application-context prefixing, or an empty string when none is specified
     */
    public function getCallbackURI(): string
    {
        return $this->callbackURI;
    }
}
