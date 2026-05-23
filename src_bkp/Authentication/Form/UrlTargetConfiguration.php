<?php

namespace Lucinda\WebSecurity\Authentication\Form;

/**
 * Reads XML to get source/target urls for login/logout
 */
abstract class UrlTargetConfiguration extends UrlTargets
{
    /**
     * Get name of XML sub-tag holding source/target url values
     *
     * @return string
     */
    abstract protected function getTagName(): string;

    /**
     * Sets source and destination pages based on XML
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setSourcePage($xml);
        $this->setDestinationPage($xml);
    }

    /**
     * Sets current page.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setSourcePage(\SimpleXMLElement $xml): void
    {
        $tag = $this->getTagName();
        $this->sourcePage = (string) $xml->$tag["page"];
    }

    /**
     * Sets page to redirect to on login success/failure.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setDestinationPage(\SimpleXMLElement $xml): void
    {
        $tag = $this->getTagName();
        $this->targetPage = (string) $xml->$tag["target"];
    }
}
