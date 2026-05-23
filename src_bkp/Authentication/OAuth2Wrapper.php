<?php

namespace Lucinda\WebSecurity\Authentication;

use Lucinda\WebSecurity\Authentication\OAuth2\Authentication;
use Lucinda\WebSecurity\Authentication\OAuth2\VendorAuthenticationDAO;
use Lucinda\WebSecurity\Token\EncryptionException;
use Lucinda\WebSecurity\Token\Exception as TokenException;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\CsrfTokenDetector;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\Authentication\OAuth2\Driver as OAuth2Driver;
use Lucinda\WebSecurity\Authentication\OAuth2\Exception as OAuth2Exception;
use Lucinda\WebSecurity\Authentication\OAuth2\XMLParser;
use Lucinda\WebSecurity\ConfigurationException;

/**
 * Perform login/logout via an oauth2 vendor (eg: facebook) if path requested matches that @ xml.
 */
class OAuth2Wrapper extends Wrapper
{
    private XMLParser $xmlParser;
    private Authentication $driver;

    /**
     * Creates an object
     *
     * @param  \SimpleXMLElement   $xml                XML holding information relevant to authentication
     * @param  Request             $request            Encapsulated client request data.
     * @param  CsrfTokenDetector   $csrf               Driver performing CSRF validation
     * @param  PersistenceDriver[] $persistenceDrivers Drivers where authenticated state is persisted (eg: session).
     * @param  OAuth2Driver[]      $drivers            List of oauth2 drivers detected
     * @throws ConfigurationException If POST parameters are not provided when logging in or DAO classes are mis-configured.
     * @throws TokenException If CSRF checks fail
     * @throws OAuth2Exception|EncryptionException If vendor responds with an error
     */
    public function __construct(
        \SimpleXMLElement $xml,
        Request $request,
        CsrfTokenDetector $csrf,
        array $persistenceDrivers,
        array $drivers
    ) {
        if (empty($drivers)) {
            return; // in case no drivers are active (localhost), disable authentication
        }

        $this->xmlParser = new XMLParser($xml);

        // setup class properties
        $this->driver = new Authentication($this->getDAO($xml), $persistenceDrivers);

        // checks if login was requested
        foreach ($drivers as $driver) {
            if ($driver->getCallbackUrl() == $request->getUri()) {
                $this->login($driver, $request, $csrf);
            }
        }

        // checks if a logout action was requested
        if ($this->xmlParser->getLogoutCallback() == $request->getUri()) {
            $this->logout();
        }
    }

    /**
     * Logs user in (and registers if not found)
     *
     * @param  OAuth2Driver      $driverInfo Name of oauth2 driver (eg: facebook)
     * @param  Request           $request    Encapsulated client request data.
     * @param  CsrfTokenDetector $csrf       Object that performs CSRF token checks.
     * @throws TokenException|OAuth2Exception|EncryptionException
     */
    private function login(OAuth2Driver $driverInfo, Request $request, CsrfTokenDetector $csrf): void
    {
        // detect parameters from xml
        $parameters = $request->getParameters();
        if (!empty($parameters["code"])) {
            if (empty($parameters["state"]) || !$csrf->isValid($parameters["state"], 0)) {
                throw new TokenException("CSRF token is invalid or missing!");
            }
            $result = $this->driver->login($driverInfo, $parameters["code"]);
            $this->setResult($result, $this->xmlParser->getLoginCallback(), $this->xmlParser->getTargetCallback());
        } elseif (!empty($parameters["error"])) {
            $exception = new OAuth2Exception($parameters["error"]);
            $exception->setErrorCode($parameters["error"]);
            $exception->setErrorDescription($parameters["error_description"] ??  "");
            throw $exception;
        } else {
            // set result
            $result = new Result(ResultStatus::DEFERRED);
            $result->setCallbackURI($driverInfo->getAuthorizationCode($csrf->generate(0)));
            $this->result = $result;
        }
    }

    /**
     * Logs user out and empties all tokens for that user.
     */
    private function logout(): void
    {
        $result = $this->driver->logout();
        $this->setResult($result, $this->xmlParser->getLoginCallback(), $this->xmlParser->getLoginCallback());
    }

    /**
     * Gets DAO where authentication is saved
     *
     * @param  \SimpleXMLElement $xml
     * @throws ConfigurationException
     * @return VendorAuthenticationDAO
     * @throws ConfigurationException
     */
    private function getDAO(\SimpleXMLElement $xml): VendorAuthenticationDAO
    {
        $className = (string) $xml->authentication->oauth2["dao"];
        if (!$className) {
            throw new ConfigurationException("Attribute 'dao' is mandatory for 'oauth2' tag");
        }
        return new $className();
    }
}
