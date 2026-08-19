<?php

namespace Lucinda\WebSecurity\Detectors;

use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Configuration as SecurityConfiguration;
use Lucinda\WebSecurity\Configuration\Authentication\Form as FormAuthentication;

/**
 * Detects whether remember-me was selected during login.
 */
final class RememberMeTicked
{
    private bool $status;

    /**
     * Sets up object state.
     *
     * @param SecurityConfiguration $configuration
     * @param Request $request
     */
    public function __construct(SecurityConfiguration $configuration, Request $request)
    {
        $this->status = $this->setTicked($configuration, $request);
    }

    /**
     * Detects remember-me selection from request parameters.
     *
     * @param SecurityConfiguration $configuration
     * @param Request $request
     * @return bool
     */
    private function setTicked(SecurityConfiguration $configuration, Request $request): bool
    {
        if ($request->getMethod()!== "POST") {
            return false;
        }

        $rememberMeParam = "";
        foreach ($configuration->getAuthentication()->getLoginMethods() as $method) {
            if ($method instanceof FormAuthentication) {
                $rememberMeParam = $method->getParameterRememberMe();
            }
        }

        return $rememberMeParam && !empty($request->getParameters()[$rememberMeParam]);
    }

    /**
     * Gets remember-me selection status.
     *
     * @return bool
     */
    public function getTicked(): bool
    {
        return $this->status;
    }
}
