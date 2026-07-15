<?php

namespace Lucinda\WebSecurity\Configuration;

use Lucinda\WebSecurity\Configuration\Authorization\ByDAO;
use Lucinda\WebSecurity\Configuration\Authorization\ByXML;

/**
 * Encapsulates Authorization logic.
 */
final class Authorization
{
    private array $methods = [];

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        if (!isset($xml->authorization)) {
            throw new Exception("Tag 'authorization', child of 'security' is required!");
        }
        $subXML = $xml->authorization;

        $this->setMethods($subXML);
    }

    /**
     * Sets methods.
     *
     * @param \SimpleXMLElement $xml
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
     * Gets methods.
     *
     * @return array
     */
    public function getMethods(): array
    {
        return $this->methods;
    }
}
