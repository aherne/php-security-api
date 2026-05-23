<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Authentication\DAOWrapper;
use Lucinda\WebSecurity\Authentication\XMLWrapper;
use Lucinda\WebSecurity\Authentication\OAuth2Wrapper;
use Lucinda\WebSecurity\Authentication\Wrapper as AuthenticationWrapper;
use Lucinda\WebSecurity\Authentication\ResultStatus;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\Authentication\OAuth2\Driver as OAuth2Driver;

/**
 * Performs user authentication based on mechanism chosen by developmer in XML (eg: from database via login form, from an oauth2 provider, etc)
 */
class Authentication
{
    /**
     * Detects authentication methods
     *
     * @param  \SimpleXMLElement   $xml
     * @param  Request             $request
     * @param  CsrfTokenDetector   $csrfTokenDetector
     * @param  PersistenceDriver[] $persistenceDrivers
     * @param  OAuth2Driver[]      $oauth2Drivers
     * @throws \Exception
     */
    public function __construct(
        \SimpleXMLElement $xml,
        Request $request,
        CsrfTokenDetector $csrfTokenDetector,
        array $persistenceDrivers,
        array $oauth2Drivers
    ) {
        $wrappers = $this->getWrappers($xml, $request, $csrfTokenDetector, $persistenceDrivers, $oauth2Drivers);
        foreach ($wrappers as $wrapper) {
            $this->authenticate($wrapper, $request, $persistenceDrivers);
        }
    }

    /**
     * Detects authentication methods and performs authentication if needed
     *
     * @param  \SimpleXMLElement   $xmlRoot
     * @param  Request             $request
     * @param  CsrfTokenDetector   $csrfTokenDetector
     * @param  PersistenceDriver[] $persistenceDrivers
     * @param  OAuth2Driver[]      $oauth2Drivers
     * @return AuthenticationWrapper[]
     * @throws \Exception
     */
    private function getWrappers(
        \SimpleXMLElement $xmlRoot,
        Request $request,
        CsrfTokenDetector $csrfTokenDetector,
        array $persistenceDrivers,
        array $oauth2Drivers
    ): array {
        $wrappers = [];
        $xml = $xmlRoot->authentication;
        if (empty($xml)) {
            throw new ConfigurationException("Tag 'authentication' child of 'security' is empty or missing");
        }

        if ($xml->form) {
            if ((string) $xml->form["dao"]) {
                $wrappers[] = new DAOWrapper(
                    $xmlRoot,
                    $request,
                    $csrfTokenDetector,
                    $persistenceDrivers
                );
            } else {
                $wrappers[] = new XMLWrapper(
                    $xmlRoot,
                    $request,
                    $csrfTokenDetector,
                    $persistenceDrivers
                );
            }
        }
        if ($xml->oauth2) {
            $wrappers[] = new OAuth2Wrapper(
                $xmlRoot,
                $request,
                $csrfTokenDetector,
                $persistenceDrivers,
                $oauth2Drivers
            );
        }
        if (empty($wrappers)) {
            throw new ConfigurationException("No authentication method chosen!");
        }
        return $wrappers;
    }

    /**
     * Handles results of authentication, if any was requested, by throwing a SecurityPacket
     *
     * @param  AuthenticationWrapper $wrapper
     * @param  Request               $request
     * @param  PersistenceDriver[]   $persistenceDrivers
     * @throws SecurityPacket
     */
    private function authenticate(
        AuthenticationWrapper $wrapper,
        Request $request,
        array $persistenceDrivers
    ): void {
        if ($wrapper->getResult()) {
            // authentication was requested
            $transport = new SecurityPacket();
            if ($wrapper->getResult()->getStatus()==ResultStatus::DEFERRED) {
                $transport->setCallback($wrapper->getResult()->getCallbackURI());
            } else {
                $transport->setCallback($request->getContextPath()."/".$wrapper->getResult()->getCallbackURI());
            }
            $transport->setStatus($wrapper->getResult()->getStatus());
            $transport->setAccessToken($wrapper->getResult()->getUserID(), $persistenceDrivers);
            $transport->setTimePenalty($wrapper->getResult()->getTimePenalty());
            throw $transport;
        }
    }
}
