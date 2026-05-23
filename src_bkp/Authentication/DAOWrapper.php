<?php

namespace Lucinda\WebSecurity\Authentication;

use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\CsrfTokenDetector;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\Authentication\DAO\UserAuthenticationDAO;
use Lucinda\WebSecurity\Authentication\DAO\Authentication;
use Lucinda\WebSecurity\Authentication\Form\LoginRequest;
use Lucinda\WebSecurity\Authentication\Form\LogoutRequest;
use Lucinda\WebSecurity\Token\Exception as TokenException;
use Lucinda\WebSecurity\ConfigurationException;

/**
 * Performs login/logout via database if path requested matches paths @ xml
 */
class DAOWrapper extends FormWrapper
{
    private Authentication $driver;

    /**
     * Creates an object.
     *
     * @param  \SimpleXMLElement   $xml                XML holding information relevant to authentication
     * @param  Request             $request            Encapsulated client request data.
     * @param  CsrfTokenDetector   $csrfTokenDetector  Driver performing CSRF validation
     * @param  PersistenceDriver[] $persistenceDrivers Drivers where authenticated state is persisted (eg: session).
     * @throws ConfigurationException
     * @throws Form\Exception
     * @throws TokenException
     */
    public function __construct(
        \SimpleXMLElement $xml,
        Request $request,
        CsrfTokenDetector $csrfTokenDetector,
        array $persistenceDrivers
    ) {
        $this->driver = new Authentication($this->getDAO($xml), $persistenceDrivers);
        $this->process($xml, $request, $csrfTokenDetector);
    }

    /**
     * Gets DAO where authentication is performed
     *
     * @param  \SimpleXMLElement $xml
     * @return UserAuthenticationDAO
     * @throws ConfigurationException
     */
    private function getDAO(\SimpleXMLElement $xml): UserAuthenticationDAO
    {
        $className = (string) $xml->authentication->form["dao"];
        if (!$className) {
            throw new ConfigurationException("Attribute 'dao' is mandatory for 'form' tag");
        }
        return new $className();
    }

    /**
     * Logs user in authentication driver.
     *
     * @param LoginRequest $request Encapsulates login request data.
     */
    protected function login(LoginRequest $request): void
    {
        // set result
        $result = $this->driver->login(
            $request->getUsername(),
            $request->getPassword(),
            $request->isRememberMe()
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
