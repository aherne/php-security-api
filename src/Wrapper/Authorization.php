<?php

namespace Lucinda\WebSecurity\Wrapper;

use Lucinda\WebSecurity\Configuration;
use Lucinda\WebSecurity\Configuration\RolesDetector;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authorization as SecurityAuthorization;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus as AuthorizationStatus;

/**
 * Binds resource-authorization decisions to caller-facing security packets
 *
 * Connects the main configuration, current request, authenticated user ID,
 * and optional route-role detector to Security\Authorization. Converts denied
 * access into a security packet with an application-context-prefixed callback.
 * Allowed access produces no packet, allowing the parent workflow to continue.
 *
 * Construction binds dependencies; run() performs the authorization check.
 *
 * @internal
 * @see \Lucinda\WebSecurity\Wrapper
 * @see \Lucinda\WebSecurity\Security\Authorization
 * @see \Lucinda\WebSecurity\Security\Authorization\Result
 * @see \Lucinda\WebSecurity\Packets\Security
 */
final class Authorization
{
    private Configuration $configuration;
    private Request $request;
    private ?RolesDetector $rolesDetector;
    private int|string|null $authenticatedUserID;
    

    /**
     * Binds authorization dependencies without checking access
     *
     * @param Configuration $configuration Main security configuration containing authorization settings
     * @param Request $request Request whose route and HTTP method are to be authorized
     * @param RolesDetector|null $rolesDetector Pre-parsed route-role policies, required for XML-based authorization
     * @param int|string|null $authenticatedUserID Fully authenticated local user ID, or null for a guest
     */
    public function __construct(
        Configuration $configuration,
        Request $request,
        ?RolesDetector $rolesDetector = null,
        int|string|null $authenticatedUserID = null
        )
    {
        $this->configuration = $configuration;
        $this->request = $request;
        $this->rolesDetector = $rolesDetector;
        $this->authenticatedUserID = $authenticatedUserID;
    }

    /**
     * Executes authorization and converts denied access into a security packet
     *
     * Prefixes a non-empty failure route with the application's context path.
     * Does not perform the redirect or change authentication persistence.
     *
     * @return SecurityPacket|null Denied-access outcome, or null when access is allowed or no decision is produced
     * @throws \Lucinda\WebSecurity\Security\Exception If XML-based authorization lacks a roles detector
     * @throws \Throwable If a configured authorization DAO fails
     */
    public function run(): ?SecurityPacket
    {
        $validator = new SecurityAuthorization(
            $this->configuration->getAuthorization(),
            $this->request,
            $this->authenticatedUserID,
            $this->rolesDetector
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
