<?php

namespace Lucinda\WebSecurity\Authentication\Form;

/**
 * Encapsulates generic data about login/logout request
 */
abstract class UrlTargetRequest extends UrlTargets
{
    /**
     * Gets default login/logout source page, if none set in XML
     *
     * @return string
     */
    abstract protected function getDefaultSourcePage(): string;

    /**
     * Gets default login/logout target page, if none set in xml
     *
     * @return string
     */
    abstract protected function getDefaultDestinationPage(): string;

    /**
     * Sets current page.
     *
     * @param string $sourcePage
     */
    public function setSourcePage(string $sourcePage): void
    {
        $this->sourcePage = ($sourcePage ? $sourcePage : $this->getDefaultSourcePage());
    }

    /**
     * Sets page to redirect to on login/logout success/failure.
     *
     * @param string $targetPage
     */
    public function setDestinationPage(string $targetPage): void
    {
        $this->targetPage = ($targetPage ? $targetPage : $this->getDefaultDestinationPage());
    }
}
