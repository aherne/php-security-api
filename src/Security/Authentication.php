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
 * Encapsulates Authentication logic.
 */
final class Authentication
{
    private ?Packet $outcome = null;

    /**
     * Sets up object state.
     *
     * @param ConfigurationAuthentication $configuration
     * @param Request $request
     * @param int|string|null $userID
     * @param CsrfToken $csrfTokenDetector
     * @param array $oauth2Drivers
     * @param ?OAuth2State $oauth2State
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
     * Authenticate by form.
     *
     * @param ConfigurationAuthenticationForm $configuration
     * @param Request $request
     * @param int|string|null $userID
     * @param ?CsrfToken $csrfTokenDetector
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
     * Authenticate by OAuth2.
     *
     * @param ConfigurationAuthenticationOauth2 $configuration
     * @param Request $request
     * @param int|string|null $userID
     * @param array $oauth2Drivers
     * @param OAuth2State $oauth2State
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
     * Gets outcome.
     *
     * @return ?Packet
     */
    public function getOutcome(): ?Packet
    {
        return $this->outcome;
    }
}
