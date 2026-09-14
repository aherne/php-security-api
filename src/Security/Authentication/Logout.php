<?php

namespace Lucinda\WebSecurity\Security\Authentication;

use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Lucinda\WebSecurity\Configuration\Authentication\Logout as Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\DAO\Logout as LogoutDAO;
use Lucinda\WebSecurity\Security\FailureReason;

/**
 * Validates logout requests and produces the logout DAO's outcome
 *
 * Construction processes the configured logout route. Existing users must
 * submit a POST request with a valid user-bound CSRF token before the DAO
 * is invoked. Guests are deferred to the success callback. Acceptance does
 * not clear persistence here; that is handled by the enclosing wrapper.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authentication\Logout
 * @see \Lucinda\WebSecurity\DAO\Logout
 * @see \Lucinda\WebSecurity\Wrapper\Authentication
 */
final class Logout extends Generic
{
    private LogoutDAO $dao;

    /**
     * Constructs the logout handler and evaluates a matching logout request
     *
     * Leaves the outcome unset when the request does not target the logout route.
     *
     * @param Configuration $configuration Parsed logout route, CSRF parameter, and DAO class
     * @param Request $request Current request to evaluate
     * @param CsrfToken $csrfTokenDetector Validator for the user-bound logout CSRF token
     * @param int|string|null $userID Current local user ID, or null for a guest
     * @throws \Throwable If DAO initialization or logout processing fails
     */
    public function __construct(
        Configuration $configuration,
        Request $request,
        CsrfToken $csrfTokenDetector,
        int|string|null $userID
        )
    {
        if ($request->getUri() !== $configuration->getPageSource()) {
            return;
        }

        $this->request = $request;
        $this->userID = $userID;
        $daoClass = $configuration->getDAO();
        $this->dao = new $daoClass();
        $this->outcome = $this->logout(
            $configuration,
            $csrfTokenDetector,
            );
    }

    /**
     * Validates the matched logout request and invokes the logout DAO
     *
     * Expected request, CSRF, and DAO rejections become LOGOUT_FAILED packets
     * with detailed failure reasons. A guest receives a DEFERRED outcome.
     *
     * @param Configuration $configuration Parsed logout settings and callbacks
     * @param CsrfToken $csrfTokenDetector Validator for the user-bound logout CSRF token
     * @return SecurityPacket Logout acceptance, rejection, or deferral outcome
     * @throws \Throwable If the logout DAO fails outside an expected rejection
     */
    private function logout(Configuration $configuration, CsrfToken $csrfTokenDetector): SecurityPacket
    {
        if (empty($this->userID)) { // already logged out
            return new SecurityPacket(
                ResultStatus::DEFERRED,
                $this->getCallback($configuration->getTargetSuccess())
                );
        }
        
        $parameters = $this->request->getParameters();
        $csrfParameter = $configuration->getParameterCsrf();
        $csrfToken = $parameters[$csrfParameter] ?? null;
        if (
            $this->request->getMethod() !== "POST"
            || !is_string($csrfToken)
            || $csrfToken === ""
            ) {
            return new SecurityPacket(
                ResultStatus::LOGOUT_FAILED,
                $this->getCallback($configuration->getTargetFailure()),
                FailureReason::LOGOUT_PARAMETERS_INVALID
                );
        }

        if (!$csrfTokenDetector->isValid($csrfToken, $this->userID)) {
            return new SecurityPacket(
                ResultStatus::LOGOUT_FAILED,
                $this->getCallback($configuration->getTargetFailure()),
                FailureReason::LOGOUT_CSRF_REJECTED
                );
        }

        if ($this->dao->logout($this->userID)) {
            return new SecurityPacket(
                ResultStatus::LOGOUT_OK,
                $this->getCallback($configuration->getTargetSuccess())
                );
        } else {
            return new SecurityPacket(
                ResultStatus::LOGOUT_FAILED,
                $this->getCallback($configuration->getTargetFailure()),
                FailureReason::LOGOUT_REJECTED
                );
        }
    }
}
