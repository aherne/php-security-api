<?php
namespace Lucinda\WebSecurity\Security;

use Lucinda\WebSecurity\Configuration\Authentication as ConfigurationAuthentication;
use Lucinda\WebSecurity\Configuration\Authentication\Form as ConfigurationAuthenticationForm;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2 as ConfigurationAuthenticationOauth2;
use Lucinda\WebSecurity\Configuration\Authentication\Logout as ConfigurationAuthenticationLogout;
use Lucinda\WebSecurity\Security\Authentication\Form as AuthenticatorForm;
use Lucinda\WebSecurity\Security\Authentication\Oauth2 as AuthenticatorOauth2;
use Lucinda\WebSecurity\Security\Authentication\Logout as AuthenticatorLogout;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\OAuth2State;
use Lucinda\WebSecurity\Packets\Packet;
use Lucinda\WebSecurity\Security\Exception as SecurityException;

/**
 * Selects and executes authentication handling for the current request
 *
 * Construction tries logout first, then the configured login methods until
 * one produces an outcome. The computed packet is available through
 * getOutcome(); invoking the getter does not execute authentication again.
 * The enclosing wrapper handles authentication persistence and MFA staging.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authentication
 * @see \Lucinda\WebSecurity\Wrapper\Authentication
 * @see \Lucinda\WebSecurity\Packets\Packet
 */
final class Authentication
{
    private ?Packet $outcome = null;

    /**
     * Constructs and executes the configured authentication workflow
     *
     * @param ConfigurationAuthentication $configuration Parsed login and logout configuration
     * @param Request $request Current request to evaluate
     * @param int|string|null $userID Current local user ID, or null for a guest
     * @param CsrfToken $csrfTokenDetector CSRF token generator and validator
     * @param array<string,\Lucinda\WebSecurity\OAuth2Service> $oauth2Drivers Provider services keyed by configured provider name
     * @param OAuth2State|null $oauth2State OAuth2 state store, required when evaluating OAuth2 configuration
     * @throws SecurityException If required OAuth2 services or state storage are missing
     * @throws \Throwable If an invoked DAO, provider, state store, or token operation fails
     */
    public function __construct(
        ConfigurationAuthentication $configuration,
        Request $request,
        int|string|null $userID,
        CsrfToken $csrfTokenDetector,
        array $oauth2Drivers = [],
        ?OAuth2State $oauth2State = null
        )
    {
        $logoutConfiguration = $configuration->getLogoutMethod();
        $this->outcome = $this->logout($logoutConfiguration, $request, $userID, $csrfTokenDetector);
        if ($this->outcome) {
            return;
        }

        $methods = $configuration->getLoginMethods();
        foreach ($methods as $subConfiguration) {
            if ($this->outcome) {
                break; // outcome has already been detected
            }

            if ($subConfiguration instanceof ConfigurationAuthenticationForm) {
                $this->outcome = $this->loginByForm($subConfiguration, $request, $userID, $csrfTokenDetector);
            } else {
                if (empty($oauth2Drivers) || $oauth2State === null) {
                    throw new SecurityException("Oauth2 drivers and state are mandatory for oauth2 login!");
                }
                $this->outcome = $this->loginByOauth2($subConfiguration, $request, $userID, $oauth2Drivers, $oauth2State);
            }
        }
    }

    /**
     * Delegates the request to the configured logout handler
     *
     * @param ConfigurationAuthenticationLogout $configuration Parsed logout configuration
     * @param Request $request Current request to evaluate
     * @param int|string|null $userID Current local user ID, or null for a guest
     * @param CsrfToken $csrfTokenDetector Validator for the logout CSRF token
     * @return Packet|null Logout outcome, or null when the request does not target logout
     * @throws \Throwable If logout processing fails outside an expected rejection
     */
    private function logout(
        ConfigurationAuthenticationLogout $configuration,
        Request $request,
        int|string|null $userID,
        CsrfToken $csrfTokenDetector
    ): ?Packet
    {
        $authenticator = new AuthenticatorLogout($configuration, $request, $csrfTokenDetector, $userID);
        return $authenticator->getOutcome();
    }

    /**
     * Delegates the request to the configured form-login handler
     *
     * @param ConfigurationAuthenticationForm $configuration Parsed form-login configuration
     * @param Request $request Current request to evaluate
     * @param int|string|null $userID Current local user ID, or null for a guest
     * @param CsrfToken $csrfTokenDetector Generator and validator for guest login CSRF tokens
     * @return Packet|null Form-login outcome, or null when the request does not target the login route
     * @throws \Throwable If a DAO, throttler, or token operation fails
     */
    private function loginByForm(
        ConfigurationAuthenticationForm $configuration,
        Request $request,
        int|string|null $userID,
        CsrfToken $csrfTokenDetector
        ): ?Packet
    {
        $authenticator = new AuthenticatorForm($configuration, $request, $csrfTokenDetector, $userID);
        return $authenticator->getOutcome();
    }

    /**
     * Delegates the request to the configured OAuth2 login handler
     *
     * @param ConfigurationAuthenticationOauth2 $configuration Parsed OAuth2 configuration
     * @param Request $request Current request to evaluate
     * @param int|string|null $userID Current local user ID, or null for a guest
     * @param array<string,\Lucinda\WebSecurity\OAuth2Service> $oauth2Drivers Provider services keyed by configured provider name
     * @param OAuth2State $oauth2State Store used to save and consume provider-bound login state
     * @return Packet|null OAuth2 outcome, or null when no configured provider route matches
     * @throws SecurityException If a configured provider service was not supplied
     * @throws \Throwable If a provider, state-store, or DAO operation fails
     */
    private function loginByOauth2(
        ConfigurationAuthenticationOauth2 $configuration,
        Request $request,
        int|string|null $userID,
        array $oauth2Drivers,
        OAuth2State $oauth2State
        ): ?Packet
    {
        $authenticator = new AuthenticatorOauth2($configuration, $request, $userID, $oauth2Drivers, $oauth2State);
        return $authenticator->getOutcome();
    }

    /**
     * Gets the authentication outcome computed during construction
     *
     * @return Packet|null Computed outcome, or null when no authentication handler produced one
     */
    public function getOutcome(): ?Packet
    {
        return $this->outcome;
    }
}
