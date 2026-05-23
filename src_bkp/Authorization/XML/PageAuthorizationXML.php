<?php

namespace Lucinda\WebSecurity\Authorization\XML;

use Lucinda\WebSecurity\ConfigurationException;

/**
 * Encapsulates route authorization via <routes> XML tag
 */
class PageAuthorizationXML
{
    private \SimpleXMLElement $xml;

    /**
     * Sets XML to authorize into
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->xml = $xml;
    }

    /**
     * Gets roles from XML
     *
     * @param  string $routeToAuthorize
     * @return string[]
     * @throws ConfigurationException
     */
    public function getRoles(string $routeToAuthorize): array
    {
        $detector = new RolesDetector($this->xml, "routes", "route", "id", $routeToAuthorize);
        return $detector->getRoles();
    }
}
