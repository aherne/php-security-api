<?php

namespace Lucinda\WebSecurity\Security\Authentication;

use Lucinda\WebSecurity\DAO\Throttler\FormLogin as FormLoginThrottler;
use Lucinda\WebSecurity\DAO\FormAuthentication;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Lucinda\WebSecurity\Configuration\Authentication\Form as Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\Configuration\Authentication\Form\Login as LoginPolicy;
use Lucinda\WebSecurity\Configuration\Authentication\Form\Logout as LogoutPolicy;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Packets\GuestUser;

/**
 * Encapsulates Form logic.
 */
final class Form extends Generic
{
    private FormAuthentication $dao;

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
        $this->request = $request;
        $this->userID = $userID;

        $daoClass = $configuration->getDAO();
        $this->dao = new $daoClass();

        $throttlerClass = $configuration->getThrottler();

        $loginPolicy = $configuration->getLoginPolicy();
        if ($request->getUri() === $loginPolicy->getPageSource()) {
            $this->outcome = $this->login(
                $loginPolicy,
                $csrfTokenDetector,
                new $throttlerClass()
                );
        }

        $logoutPolicy = $configuration->getLogoutPolicy();
        if ($request->getUri() === $logoutPolicy->getPageSource()) {
            $this->outcome = $this->logout(
                $logoutPolicy
                );
        }
    }

    /**
     * Processes login.
     *
     * @param LoginPolicy $configuration
     * @param CsrfToken $csrfTokenDetector
     * @param FormLoginThrottler $throttler
     * @return SecurityPacket|ThrottlingPacket|GuestUser
     */
    private function login(LoginPolicy $configuration, CsrfToken $csrfTokenDetector, FormLoginThrottler $throttler): SecurityPacket|ThrottlingPacket|GuestUser
    {
        if ($this->userID !== null) { // already logged in
            return new SecurityPacket(
                ResultStatus::DEFERRED,
                $this->getCallback($configuration->getTargetSuccess())
                );
        }

        if ($this->request->getMethod() === "POST") { // login is attempted
            $parameters = $this->request->getParameters();

            // check parameters
            $csrfParameter = $configuration->getParameterCsrf();
            $usernameParameter = $configuration->getParameterUsername();
            $passwordParameter = $configuration->getParameterPassword();
            if (empty($parameters[$csrfParameter]) || empty($parameters[$usernameParameter]) || empty($parameters[$passwordParameter])) {
                return new SecurityPacket(ResultStatus::LOGIN_FAILED, $this->getCallback($configuration->getTargetFailure()));
            }
            $username = $parameters[$usernameParameter];
            $password = $parameters[$passwordParameter];
            $ipAddress = $this->request->getIpAddress();

            // check if throttled already
            if ($throttler->isThrottled($username, $ipAddress)) {
                return $this->throttle($configuration->getTargetThrottled());
            }

            // check if csrf token is invalid or missing
            if (!$csrfTokenDetector->isValid($parameters[$csrfParameter], 0)) {
                return new SecurityPacket(
                    ResultStatus::LOGIN_FAILED,
                    $this->getCallback($configuration->getTargetFailure())
                );
            }

            // attempt login
            $outcome = $this->dao->login($username, $password);
            if ($outcome !== null) {
                $packet = new SecurityPacket(ResultStatus::IDENTITY_VERIFIED, $this->getCallback($configuration->getTargetSuccess()));
                $packet->setUserID($outcome);
                return $packet;
            } else { // penalize for failing login
                $throttler->penalize($username, $ipAddress);
                if ($throttler->isThrottled($username, $ipAddress)) {
                    return $this->throttle($configuration->getTargetThrottled());
                }
                return new SecurityPacket(ResultStatus::LOGIN_FAILED, $this->getCallback($configuration->getTargetFailure()));
            }
        }

        return new GuestUser(
            $csrfTokenDetector->generate(0) // we are in login page and have a csrf token generated
        );
    }

    /**
     * Processes logout.
     *
     * @param LogoutPolicy $configuration
     * @return SecurityPacket
     */
    private function logout(LogoutPolicy $configuration): SecurityPacket
    {
        if ($this->userID === null) { // already logged out
            return new SecurityPacket(
                ResultStatus::DEFERRED,
                $this->getCallback($configuration->getTargetSuccess())
                );
        }

        if ($this->dao->logout($this->userID)) {
            return new SecurityPacket(ResultStatus::LOGOUT_OK, $this->getCallback($configuration->getTargetSuccess()));
        } else {
            return new SecurityPacket(ResultStatus::LOGOUT_FAILED, $this->getCallback($configuration->getTargetFailure()));
        }
    }

    /**
     * Composes a throttling packet to answer when user will be refused authentication
     * 
     * @return ThrottlingPacket
     */
    private function throttle(string $callback): ThrottlingPacket
    {
        $packet = new ThrottlingPacket(ResultStatus::LOGIN_THROTTLED);
        $packet->setCallback($this->getCallback($callback));
        return $packet;
    }
}
