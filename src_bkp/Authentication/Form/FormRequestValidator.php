<?php

namespace Lucinda\WebSecurity\Authentication\Form;

use Lucinda\WebSecurity\Request;

/**
 * Validates authentication requests in configuration.xml and encapsulates them into objects
 */
class FormRequestValidator
{
    private \SimpleXMLElement $xml;
    private Request $request;

    /**
     * Matches POST request to XML tag &lt;form&gt;
     *
     * @param \SimpleXMLElement $xml
     * @param Request           $request
     */
    public function __construct(\SimpleXMLElement $xml, Request $request)
    {
        $this->xml = $xml->authentication->form;
        $this->request = $request;
    }

    /**
     * Performs a form login
     *
     * @throws Exception
     * @return LoginRequest|NULL
     */
    public function login(): ?LoginRequest
    {
        $requestParameters = $this->request->getParameters();

        $configuration = new LoginConfiguration($this->xml);

        $loginRequest = new LoginRequest();
        $loginRequest->setSourcePage($configuration->getSourcePage());
        if ($loginRequest->getSourcePage() != $this->request->getUri() || $this->request->getMethod() != "POST") {
            return null;
        }
        $loginRequest->setDestinationPage($configuration->getDestinationPage());
        $parameterUsername = $configuration->getUsername();
        if (!isset($requestParameters[$parameterUsername])) {
            throw new Exception("POST parameter missing: ".$parameterUsername);
        }
        $loginRequest->setUsername($requestParameters[$parameterUsername]);
        $parameterPassword = $configuration->getPassword();
        if (!isset($requestParameters[$parameterPassword])) {
            throw new Exception("POST parameter missing: ".$parameterPassword);
        }
        $loginRequest->setPassword($requestParameters[$parameterPassword]);
        $loginRequest->setRememberMe(!empty($requestParameters[$configuration->getRememberMe()]));

        return $loginRequest;
    }

    /**
     * Performs a form logout
     *
     * @return LogoutRequest|NULL
     */
    public function logout(): ?LogoutRequest
    {
        $configuration = new LogoutConfiguration($this->xml);

        $logoutRequest = new LogoutRequest();
        $logoutRequest->setSourcePage($configuration->getSourcePage());
        if ($logoutRequest->getSourcePage() != $this->request->getUri()) {
            return null;
        }
        $logoutRequest->setDestinationPage($configuration->getDestinationPage());

        return $logoutRequest;
    }
}
