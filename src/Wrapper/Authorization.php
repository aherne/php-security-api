<?php

namespace Lucinda\WebSecurity\Wrapper;

use Lucinda\WebSecurity\Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authorization as SecurityAuthorization;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus as AuthorizationStatus;

final class Authorization
{
    private Configuration $configuration;
    private Request $request;
    private ?\SimpleXMLElement $routes;
    private int|string|null $authenticatedUserID;
    

    public function __construct(
        Configuration $configuration,
        Request $request,
        ?\SimpleXMLElement $routes = null,
        int|string|null $authenticatedUserID = null
        )
    {
        $this->configuration = $configuration;
        $this->request = $request;
        $this->routes = $routes;
        $this->authenticatedUserID = $authenticatedUserID;
    }

    public function run(): ?SecurityPacket
    {
        $validator = new SecurityAuthorization(
            $this->configuration->getAuthorization(),
            $this->request,
            $this->authenticatedUserID,
            !empty($this->routes->routes) ? $this->routes : null
            );
        if ($outcome = $validator->getOutcome()) {
            if ($outcome->getStatus() == AuthorizationStatus::OK) {
                return null;
            }

            $callback = $outcome->getCallbackURI();
            if ($callback) {
                $callback = $this->request->getContextPath()."/".$callback;
            }
            return new SecurityPacket($outcome->getStatus(), $callback ?: null);
        }
        return null;
    }
}