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
use Lucinda\WebSecurity\Security\FailureReason;

/**
 * Executes form-login validation and produces an authentication outcome
 *
 * Construction processes requests matching the configured login route.
 * Coordinates parameter checks, throttling, guest CSRF validation, and the
 * credentials DAO. Successful credentials produce IDENTITY_VERIFIED; the
 * enclosing wrapper handles MFA staging and authentication persistence.
 * Non-POST login requests receive a guest packet with a CSRF token.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authentication\Form
 * @see \Lucinda\WebSecurity\DAO\FormLogin
 * @see \Lucinda\WebSecurity\DAO\Throttler\FormLogin
 */
final class Form extends Generic
{
    /**
     * Guest context identifier used when generating and validating form-login CSRF tokens
     */
    const GUEST_USER = "guest";
    private LoginDAO $dao;

    /**
     * Constructs the form-login handler and evaluates a matching login request
     *
     * @param Configuration $configuration Parsed form-login routes, parameters, and DAO classes
     * @param Request $request Current request to evaluate
     * @param CsrfToken $csrfTokenDetector Generator and validator for guest login CSRF tokens
     * @param int|string|null $userID Current local user ID, or null for a guest
     * @throws \Throwable If DAO initialization, throttling, or token processing fails
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
     * Evaluates the matched form-login request
     *
     * An existing user is deferred to the success callback. For a guest POST,
     * validates parameters, throttling, and CSRF before checking credentials.
     * Rejected credentials are penalized; expected rejections become packets.
     * For non-POST requests, generates a guest login CSRF token.
     *
     * @param Configuration $configuration Parsed form-login settings
     * @param CsrfToken $csrfTokenDetector Generator and validator for guest login CSRF tokens
     * @param FormLoginThrottler $throttler DAO controlling username-and-IP login throttling
     * @return SecurityPacket|ThrottlingPacket|GuestUser Login decision, throttling outcome, or guest form state
     * @throws \Throwable If a DAO, throttler, or token operation fails
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
            if (!$this->validateParameters([
                $configuration->getParameterCsrf(),
                $configuration->getParameterUsername(),
                $configuration->getParameterPassword()
            ])) {
                return new SecurityPacket(
                    ResultStatus::LOGIN_FAILED,
                    $this->getCallback($configuration->getTargetFailure()),
                    FailureReason::FORM_PARAMETERS_INVALID
                    );
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
                    $this->getCallback($configuration->getTargetFailure()),
                    FailureReason::FORM_CSRF_REJECTED
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
                return new SecurityPacket(
                    ResultStatus::LOGIN_FAILED,
                    $this->getCallback($configuration->getTargetFailure()),
                    FailureReason::FORM_CREDENTIALS_REJECTED
                    );
            }
        }

        return new GuestUser(
            $csrfTokenDetector->generate(self::GUEST_USER) // we are in login page and have a csrf token generated
        );
    }

    /**
     * Composes the form-login throttling outcome with its redirect destination
     *
     * @param string $callback Configured throttling route relative to the application context
     * @return ThrottlingPacket LOGIN_THROTTLED packet with a context-prefixed callback
     */
    private function throttle(string $callback): ThrottlingPacket
    {
        $packet = new ThrottlingPacket(ResultStatus::LOGIN_THROTTLED);
        $packet->setCallback($this->getCallback($callback));
        return $packet;
    }

    /**
     * Checks that all named request parameters contain non-empty strings
     *
     * Uses PHP empty(), so the string "0" is also rejected.
     *
     * @param string[] $keys Names of the required request parameters
     * @return bool True when every named parameter is a string accepted by the emptiness check
     */
    private function validateParameters(array $keys): bool
    {
        $parameters = $this->request->getParameters();
        foreach ($keys as $key) {
            if (empty($parameters[$key]) || !is_string($parameters[$key])) {
                return false;
            }
        }
        return true;
    }
}
