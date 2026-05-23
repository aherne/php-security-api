<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Authentication\MultiFactor;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Token\PersistenceDriver as TokenPersistenceDriver;
use Lucinda\WebSecurity\Authentication\OAuth2\Driver as OAuth2Driver;
use Lucinda\WebSecurity\Authentication\MultiFactor\ResultStatus as MfaStatus;

/**
 * Authenticates and authorizes based on contents of XML tag 'security'
 */
class Wrapper
{
    /**
     * @var PersistenceDriver[]
     */
    private array $persistenceDrivers = [];
    private string|int|null $userID;
    private CsrfTokenDetector $csrfToken;

    /**
     * Performs class logic by delegating to specialized methods
     *
     * @param  \SimpleXMLElement $xml
     * @param  Request           $request
     * @param  OAuth2Driver[]    $oauth2Drivers
     * @param  ?MultiFactor      $multiFactor
     * @throws ConfigurationException
     */
    public function __construct(
        \SimpleXMLElement $xml,
        Request $request,
        array $oauth2Drivers = [],
        ?MultiFactor $multiFactor = null
        )
    {
        // detects relevant data
        $xml = $xml->security;
        if (empty($xml)) {
            throw new ConfigurationException("XML tag 'security' is missing");
        }

        // applies web security on request
        $this->setPersistenceDrivers($xml, $request);
        $this->setUserID($request);
        if ($this->userID && $multiFactor) {
            $this->multiFactorVerification($request, $multiFactor);
        }
        $this->setCsrfToken($xml, $request);

        $this->authenticate($xml, $request, $oauth2Drivers, $multiFactor);
        $this->authorize($xml, $request);
    }

    /**
     * Sets drivers where authenticated user unique identifier is persisted based on contents of XML tag 'persistence'
     *
     * @param  \SimpleXMLElement $mainXML
     * @param  Request           $request
     * @throws ConfigurationException
     */
    private function setPersistenceDrivers(
        \SimpleXMLElement $mainXML,
        Request $request
        ): void
    {
        $pdd = new PersistenceDriversDetector($mainXML, $request->getIpAddress());
        $this->persistenceDrivers = $pdd->getPersistenceDrivers();
    }

    /**
     * Sets authenticated user unique identifier based on drivers where it was persisted into
     *
     * @param Request $request
     */
    private function setUserID(
        Request $request
        ): void
    {
        $udd = new UserIdDetector($this->persistenceDrivers, $request->getAccessToken());
        $this->userID = $udd->getUserID();
    }

    /**
     * Gets class where anti-csrf token is generated and verified
     *
     * @param  \SimpleXMLElement $mainXML
     * @param  Request           $request
     * @throws ConfigurationException
     */
    private function setCsrfToken(
        \SimpleXMLElement $mainXML,
        Request $request
        ): void
    {
        $this->csrfToken = new CsrfTokenDetector($mainXML, $request->getIpAddress());
    }

    /**
     * Performs user authentication based on mechanism chosen by developmer in XML (eg: from database via login form,
     * from an oauth2 provider, etc)
     *
     * @param  \SimpleXMLElement $mainXML
     * @param  Request           $request
     * @param  OAuth2Driver[]    $oauth2Drivers
     * @param  ?MultiFactor       $multiFactor
     * @throws \Exception
     */
    private function authenticate(
        \SimpleXMLElement $mainXML,
        Request $request,
        array $oauth2Drivers
        ): void
    {
        new Authentication($mainXML, $request, $this->csrfToken, $this->persistenceDrivers, $oauth2Drivers);
    }

    /**
     * Performs request authorization based on mechanism chosen by developmer in XML (eg: from database)
     *
     * @param  \SimpleXMLElement $mainXML
     * @param  Request           $request
     * @throws \Exception
     */
    private function authorize(
        \SimpleXMLElement $mainXML,
        Request $request
        ): void
    {
        new Authorization($mainXML, $request, $this->userID);
    }

    /**
     * Performs multi factor authentication
     *
     * @param  Request           $request
     * @param  MultiFactor       $multiFactor
     * @throws \Exception
     */
    private function multiFactorVerification(
        Request $request,
        MultiFactor $multiFactor
    ): void
    {
        new MultiFactorAuthentication($this->userID, $request, $multiFactor);
    }

    /**
     * Gets detected logged in unique user identifier
     *
     * @return int|string|null
     */
    public function getUserID(): int|string|null
    {
        return $this->userID;
    }

    /**
     * Gets a new anti-csrf token to use as value of input 'csrf' in login form
     *
     * @return string
     * @throws Token\EncryptionException
     */
    public function getCsrfToken(): string
    {
        return $this->csrfToken->generate($this->userID);
    }

    /**
     * Gets access token for stateless apps
     *
     * @return string|NULL
     */
    public function getAccessToken(): ?string
    {
        foreach ($this->persistenceDrivers as $driver) {
            if ($driver instanceof TokenPersistenceDriver) {
                return $driver->getAccessToken();
            }
        }
        return null;
    }
}
