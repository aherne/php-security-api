<?php

namespace Lucinda\WebSecurity\Configuration;

use Lucinda\WebSecurity\Configuration\Authorization\ByDAO;
use Lucinda\WebSecurity\Configuration\Authorization\ByXML;

/**
 * Encapsulates parsing of the security > authorization XML tag
 */
final class Authorization
{
    /**
     * @var array<ByDAO|ByXML>
     */
    private array $methods = [];

    /**
     * Sets up object state from the security XML tag
     *
     * @param \SimpleXMLElement $xml The security XML tag
     * @throws Exception If a required setting is missing or invalid
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        if (!isset($xml->authorization)) {
            throw new Exception("Tag 'authorization', child of 'security' is required!");
        }
        $subXML = $xml->authorization;

        $this->validate($subXML);
        $this->setMethods($subXML);
    }

    /**
     * Detects authorization configuration from 'by_dao' or 'by_route' child tags
     *
     * @param \SimpleXMLElement $xml The authorization XML tag
     * @throws Exception If neither method is configured or a child configuration is invalid
     */
    private function setMethods(\SimpleXMLElement $xml): void
    {
        if (isset($xml->by_dao)) {
            $this->methods[] = new ByDAO($xml->by_dao);
        }
        if (isset($xml->by_route)) {
            $this->methods[] = new ByXML($xml->by_route);
        }
        if (empty($this->methods)) {
            throw new Exception("Tag 'authorization' must have at least a 'by_dao' or a 'by_route' subtag!");
        }
    }

    /**
     * Validates that DAO and route authorization are not configured together
     *
     * @param \SimpleXMLElement $xml The authorization XML tag
     * @throws Exception If both 'by_dao' and 'by_route' child tags are present
     */
    private function validate(\SimpleXMLElement $xml): void
    {
        if (isset($xml->by_dao) && isset($xml->by_route)) {
            throw new Exception("Tag 'authorization' cannot have both 'by_dao' or a 'by_route' subtags!");
        }
    }

    /**
     * Gets detected authorization method configurations
     *
     * @return array<ByDAO|ByXML>
     */
    public function getMethods(): array
    {
        return $this->methods;
    }
}
