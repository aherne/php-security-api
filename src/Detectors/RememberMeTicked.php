<?php

namespace Lucinda\WebSecurity\Detectors;

use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Configuration as SecurityConfiguration;
use Lucinda\WebSecurity\Configuration\Authentication\Form as FormAuthentication;

final class RememberMeTicked
{
    private bool $status;

    public function __construct(SecurityConfiguration $configuration, Request $request)
    {
        $this->status = $this->set($configuration, $request);
    }

    private function setTicked(SecurityConfiguration $configuration, Request $request): bool
    {
        if ($request->getMethod()!== "POST") {
            return false;
        }

        $rememberMeParam = "";
        foreach ($configuration->getAuthentication()->getMethods() as $method) {
            if ($method instanceof FormAuthentication) {
                $rememberMeParam = $method->getLoginPolicy()->getParameterRememberMe();
            }
        }

        return $rememberMeParam && !empty($request->getParameters()[$rememberMeParam]);
    }

    public function getTicked(): bool
    {
        return $this->status;
    }
}
