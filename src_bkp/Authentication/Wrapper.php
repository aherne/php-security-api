<?php

namespace Lucinda\WebSecurity\Authentication;

/**
 * Defines an abstract authentication mechanism that works with AuthenticationResult
 */
abstract class Wrapper
{
    protected ?Result $result = null;

    /**
     * Sets authentication result.
     *
     * @param Result $result     Holds a reference to an object that encapsulates authentication result.
     * @param string $sourcePage Callback path to redirect to on failure.
     * @param string $targetPage Callback path to redirect to on success.
     */
    protected function setResult(Result $result, string $sourcePage, string $targetPage): void
    {
        if ($result->getStatus()==ResultStatus::LOGIN_OK || $result->getStatus()==ResultStatus::LOGOUT_OK) {
            $result->setCallbackURI($targetPage);
        } else {
            $result->setCallbackURI($sourcePage);
        }
        $this->result = $result;
    }

    /**
     * Gets authentication result.
     *
     * @return ?Result
     */
    public function getResult(): ?Result
    {
        return $this->result;
    }
}
