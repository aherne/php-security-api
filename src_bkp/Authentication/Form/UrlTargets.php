<?php

namespace Lucinda\WebSecurity\Authentication\Form;

/**
 * Blueprint of login/logout page source/target
 */
abstract class UrlTargets
{
    protected string $sourcePage;
    protected string $targetPage;

    /**
     * Gets current page.
     *
     * @return string
     */
    public function getSourcePage(): string
    {
        return $this->sourcePage;
    }

    /**
     * Gets page to redirect to on login/logout success/failure.
     *
     * @return string
     */
    public function getDestinationPage(): string
    {
        return $this->targetPage;
    }
}
