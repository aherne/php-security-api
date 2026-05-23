<?php

namespace Lucinda\WebSecurity\Authentication\OAuth2;

/**
 * Exception thrown when authentication fails on provider
 */
class Exception extends \Exception
{
    private string $errorCode;
    private string $errorDescription;

    /**
     * Sets error code
     *
     * @param string $errorCode
     */
    public function setErrorCode(string $errorCode): void
    {
        $this->errorCode = $errorCode;
    }

    /**
     * Gets error code
     *
     * @return string
     */
    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    /**
     * Sets error description
     *
     * @param string $errorDescription
     */
    public function setErrorDescription(string $errorDescription): void
    {
        $this->errorDescription = $errorDescription;
    }

    /**
     * Gets error description
     *
     * @return string
     */
    public function getErrorDescription(): string
    {
        return $this->errorDescription;
    }
}
