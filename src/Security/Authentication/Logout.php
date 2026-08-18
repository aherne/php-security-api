<?php

namespace Lucinda\WebSecurity\Security\Authentication;

use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Lucinda\WebSecurity\Configuration\Authentication\Logout as Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\DAO\Logout as LogoutDAO;

/**
 * Encapsulates logout logic.
 */
final class Logout extends Generic
{
    private LogoutDAO $dao;

    /**
     * Sets up object state.
     *
     * @param Configuration $configuration
     * @param Request $request
     * @param CsrfToken $csrfTokenDetector
     * @param int|string|null $userID
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
     * Processes logout.
     *
     * @param Configuration $configuration
     * @param CsrfToken $csrfTokenDetector
     * @return SecurityPacket
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
            || !$csrfTokenDetector->isValid($csrfToken, $this->userID)
            ) {
            return new SecurityPacket(ResultStatus::LOGOUT_FAILED, $this->getCallback($configuration->getTargetFailure()));
        }

        if ($this->dao->logout($this->userID)) {
            return new SecurityPacket(ResultStatus::LOGOUT_OK, $this->getCallback($configuration->getTargetSuccess()));
        } else {
            return new SecurityPacket(ResultStatus::LOGOUT_FAILED, $this->getCallback($configuration->getTargetFailure()));
        }
    }
}
