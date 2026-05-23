<?php

namespace Lucinda\WebSecurity\Authentication\Form;

use Lucinda\WebSecurity\Authentication\ResultStatus;
use Lucinda\WebSecurity\Authentication\Result;
use Lucinda\WebSecurity\Request;

/**
 * Encapsulates communication between LoginThrottler and \Lucinda\WebSecurity\AuthenticationResult instances
 */
class LoginThrottlerHandler
{
    private LoginThrottler $instance;

    /**
     * Sets login throttler to run validations on
     *
     * @param LoginThrottler $instance
     */
    public function __construct(LoginThrottler $instance)
    {
        $this->instance = $instance;
    }

    /**
     * Asks throttler if client is liable for a new login attempt. If not, a login failed authentication result is generated!
     *
     * @param  Request $request Encapsulated client request data.
     * @return Result|null
     */
    public function start(Request $request): ?Result
    {
        if ($penalty = $this->instance->getTimePenalty()) {
            // set login as failed, without verifying
            $result = new Result(ResultStatus::LOGIN_FAILED);
            $result->setCallbackURI($request->getUri());
            $result->setTimePenalty($penalty);
            return $result;
        }
        return null;
    }

    /**
     * Informs throttler about outcome of login attempt.
     *
     * @param Result $result
     */
    public function end(Result $result): void
    {
        $resultStatus =  $result->getStatus();
        if ($resultStatus == ResultStatus::LOGIN_OK) {
            $this->instance->setSuccess();
        } elseif ($resultStatus == ResultStatus::LOGIN_FAILED) {
            $this->instance->setFailure();
        }
    }
}
