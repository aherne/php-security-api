<?php

namespace Lucinda\WebSecurity\Authentication;

use Lucinda\WebSecurity\Authentication\Form\LoginRequest;
use Lucinda\WebSecurity\Authentication\Form\LogoutRequest;
use Lucinda\WebSecurity\CsrfTokenDetector;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\Authentication\XML\Authentication;
use Lucinda\WebSecurity\Token\EncryptionException;
use Lucinda\WebSecurity\Token\Exception as TokenException;
use Lucinda\WebSecurity\ConfigurationException;
use Lucinda\WebSecurity\Token\RegenerationException;

/**
 * Binds XMLAuthentication @ SECURITY-API to settings from configuration.xml @ SERVLETS-API then performs login/logout
 * if it matches paths @ xml via ACL @ XML.
 */
class XMLWrapper extends FormWrapper
{
    private Authentication $driver;

    /**
     * Creates an object.
     *
     * @param  \SimpleXMLElement   $xml                Contents of security.authentication.form tag @ configuration.xml.
     * @param  Request             $request            Encapsulated client request data.
     * @param  CsrfTokenDetector   $csrfTokenDetector  Driver performing CSRF validation
     * @param  PersistenceDriver[] $persistenceDrivers Drivers where authenticated state is persisted (eg: session).
     * @throws ConfigurationException
     * @throws Form\Exception
     * @throws TokenException
     * @throws EncryptionException
     * @throws RegenerationException
     */
    public function __construct(
        \SimpleXMLElement $xml,
        Request $request,
        CsrfTokenDetector $csrfTokenDetector,
        array $persistenceDrivers
    ) {
        $this->driver = new Authentication($xml->xpath("..")[0], $persistenceDrivers);
        $this->process($xml, $request, $csrfTokenDetector);
    }

    /**
     * Logs user in authentication driver.
     */
    protected function login(LoginRequest $request): void
    {
        // set result
        $result = $this->driver->login(
            $request->getUsername(),
            $request->getPassword()
        );
        $this->setResult($result, $request->getSourcePage(), $request->getDestinationPage());
    }

    /**
     * Logs user out authentication driver.
     *
     * @param LogoutRequest $request Encapsulates logout request data.
     */
    protected function logout(LogoutRequest $request): void
    {
        // set result
        $result = $this->driver->logout();
        $this->setResult($result, $request->getDestinationPage(), $request->getDestinationPage());
    }
}
