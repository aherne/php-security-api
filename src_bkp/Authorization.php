<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Authorization\ResultStatus;
use Lucinda\WebSecurity\Authorization\XMLWrapper;
use Lucinda\WebSecurity\Authorization\DAOWrapper;
use Lucinda\WebSecurity\Authorization\Wrapper as AuthorizationWrapper;

/**
 * Performs request authorization based on mechanism chosen by developmer in XML (eg: from database)
 */
class Authorization
{
    /**
     * Detects authorization methods
     *
     * @param  \SimpleXMLElement $xml
     * @param  Request           $request
     * @param  int|string|null   $userID
     * @throws SecurityPacket
     * @throws ConfigurationException
     */
    public function __construct(\SimpleXMLElement $xml, Request $request, int|string|null $userID)
    {
        $wrapper = $this->getWrapper($xml, $request, $userID);
        $this->authorize($wrapper, $request);
    }

    /**
     * Detects authorization method and performs request & user authorization
     *
     * @param  \SimpleXMLElement $xmlRoot
     * @param  Request           $request
     * @param  int|string|null   $userID
     * @throws ConfigurationException
     * @return AuthorizationWrapper
     */
    private function getWrapper(
        \SimpleXMLElement $xmlRoot,
        Request $request,
        int|string|null $userID
    ): AuthorizationWrapper {
        $xml = $xmlRoot->authorization;
        if (empty($xml)) {
            throw new ConfigurationException("Tag 'authorization' child of 'security' tag is empty or missing");
        }

        $wrapper = null;
        if ($xml->by_route) {
            $wrapper = new XMLWrapper(
                $xmlRoot,
                $request,
                $userID
            );
        }
        if ($xml->by_dao) {
            $wrapper = new DAOWrapper(
                $xmlRoot,
                $request,
                $userID
            );
        }
        if (!$wrapper) {
            throw new ConfigurationException("No authorization method chosen!");
        }
        return $wrapper;
    }

    /**
     * Handles results of failed authorization by throwing a SecurityPacket that matches type of failure
     *
     * @param  AuthorizationWrapper $wrapper
     * @param  Request              $request
     * @throws SecurityPacket
     */
    private function authorize(AuthorizationWrapper $wrapper, Request $request): void
    {
        if ($wrapper->getResult()->getStatus() != ResultStatus::OK) {
            // authorization failed
            $transport = new SecurityPacket();
            $transport->setCallback($request->getContextPath()."/".$wrapper->getResult()->getCallbackURI());
            $transport->setStatus($wrapper->getResult()->getStatus());
            throw $transport;
        }
    }
}
