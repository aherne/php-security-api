<?php

namespace Lucinda\WebSecurity\Security\Authentication;

use Lucinda\WebSecurity\DAO\Throttler\FormLogin as FormLoginThrottler;
use Lucinda\WebSecurity\Security\Authentication\ResultStatus;
use Lucinda\WebSecurity\Configuration\Authentication\Form as Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Packets\GuestUser;
use Lucinda\WebSecurity\DAO\FormLogin as LoginDAO;

/**
 * Encapsulates Form logic.
 */
final class Form extends Generic
{
    const GUEST_USER = "guest";
    private LoginDAO $dao;

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

        if ($request->getUri() === $configuration->getPageSource()) {
            $this->outcome = $this->login(
                $configuration,
                $csrfTokenDetector,
                new $throttlerClass()
                );
        }
    }

    /**
     * Processes login.
     *
     * @param Configuration $configuration
     * @param CsrfToken $csrfTokenDetector
     * @param FormLoginThrottler $throttler
     * @return SecurityPacket|ThrottlingPacket|GuestUser
     */
    private function login(Configuration $configuration, CsrfToken $csrfTokenDetector, FormLoginThrottler $throttler): SecurityPacket|ThrottlingPacket|GuestUser
    {
        if (!empty($this->userID)) { // already logged in
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
            if (!$csrfTokenDetector->isValid($parameters[$csrfParameter], self::GUEST_USER)) {
                return new SecurityPacket(
                    ResultStatus::LOGIN_FAILED,
                    $this->getCallback($configuration->getTargetFailure())
                );
            }

            // attempt login
            $outcome = $this->dao->login($username, $password);
            if (!empty($outcome)) {
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
            $csrfTokenDetector->generate(self::GUEST_USER) // we are in login page and have a csrf token generated
        );
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
