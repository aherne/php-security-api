<?php
namespace Lucinda\WebSecurity\Security;

use Lucinda\WebSecurity\Configuration\Authentication as ConfigurationAuthentication;
use Lucinda\WebSecurity\Configuration\Authentication\Form as ConfigurationAuthenticationForm;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2 as ConfigurationAuthenticationOauth2;
use Lucinda\WebSecurity\Security\Authentication\Form as AuthenticatorForm;
use Lucinda\WebSecurity\Security\Authentication\Oauth2 as AuthenticatorOauth2;
use Lucinda\WebSecurity\Packets\Security as SecurityPacket;
use Lucinda\WebSecurity\Packets\Throttling as ThrottlingPacket;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Security\Exception as SecurityException;

/**
 * Encapsulates Authentication logic.
 */
final class Authentication
{
    private SecurityPacket|ThrottlingPacket|null $outcome = null;

    /**
     * Sets up object state.
     *
     * @param ConfigurationAuthentication $configuration
     * @param Request $request
     * @param int|string|null $userID
     * @param ?CsrfToken $csrfTokenDetector
     * @param array $oauth2Drivers
     */
    public function __construct(
        ConfigurationAuthentication $configuration,
        Request $request,
        int|string|null $userID,
        ?CsrfToken $csrfTokenDetector = null,
        array $oauth2Drivers = []
        )
    {
        $methods = $configuration->getMethods();
        foreach ($methods as $subConfiguration) {
            if ($this->outcome) {
                break; // outcome has already been detected
            }

            if ($subConfiguration instanceof ConfigurationAuthenticationForm) {
                $this->outcome = $this->authenticateByForm($subConfiguration, $request, $userID, $csrfTokenDetector);
            } else {
                $this->outcome = $this->authenticateByOauth2($subConfiguration, $request, $userID, $oauth2Drivers);
            }
        }
    }

    /**
     * Authenticate by form.
     *
     * @param ConfigurationAuthenticationForm $configuration
     * @param Request $request
     * @param int|string|null $userID
     * @param ?CsrfToken $csrfTokenDetector
     */
    private function authenticateByForm(
        ConfigurationAuthenticationForm $configuration,
        Request $request,
        int|string|null $userID,
        ?CsrfToken $csrfTokenDetector = null,
        )
    {
        if ($csrfTokenDetector === null) {
            throw new SecurityException("Csrf token detector is mandatory for form login!");
        }    

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
     */
    private function authenticateByOauth2(
        ConfigurationAuthenticationOauth2 $configuration,
        Request $request,
        int|string|null $userID,
        array $oauth2Drivers = []
        )
    {
        if (empty($oauth2Drivers)) {
            throw new SecurityException("Oauth2 drivers are mandatory for oauth2 login!");
        }    

        $authenticator = new AuthenticatorOauth2($configuration, $request, $userID, $oauth2Drivers);
        return $authenticator->getOutcome();
    }

    /**
     * Gets outcome.
     *
     * @return SecurityPacket|ThrottlingPacket|null
     */
    public function getOutcome(): SecurityPacket|ThrottlingPacket|null
    {
        return $this->outcome;
    }
}
