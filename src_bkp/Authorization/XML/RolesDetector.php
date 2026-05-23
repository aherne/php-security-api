<?php

namespace Lucinda\WebSecurity\Authorization\XML;

use Lucinda\WebSecurity\ConfigurationException;

/**
 * Detects roles from matching child tag or, if not found, gets default roles
 */
class RolesDetector
{
    /**
     * @var string[]
     */
    private array $roles;

    /**
     * Calls for roles detection
     *
     * @param  \SimpleXMLElement $xml
     * @param  string            $parentTag
     * @param  string            $childTag
     * @param  string            $requiredAttribute
     * @param  int|string|null   $matchingValue
     * @throws ConfigurationException
     */
    public function __construct(
        \SimpleXMLElement $xml,
        string $parentTag,
        string $childTag,
        string $requiredAttribute,
        int|string|null $matchingValue
    ) {
        $this->setRoles($xml, $parentTag, $childTag, $requiredAttribute, $matchingValue);
    }

    /**
     * etects roles from matching child tag or, if not found, gets default roles
     *
     * @param  \SimpleXMLElement $xml
     * @param  string            $parentTag
     * @param  string            $childTag
     * @param  string            $requiredAttribute
     * @param  int|string|null   $matchingValue
     * @throws ConfigurationException
     */
    private function setRoles(
        \SimpleXMLElement $xml,
        string $parentTag,
        string $childTag,
        string $requiredAttribute,
        int|string|null $matchingValue
    ): void {
        $roles = [];
        $info = $xml->xpath("//".$parentTag."/".$childTag."[@".$requiredAttribute."='".$matchingValue."']");
        if (!empty($info)) {
            if (empty($info[0]['roles'])) {
                throw new ConfigurationException("XML tag ".$parentTag." > ".$childTag." requires attribute: roles");
            }
            $tmp = (string) $info[0]["roles"];
            $tmp= explode(",", $tmp);
            foreach ($tmp as $role) {
                $roles[] = trim($role);
            }
        }
        $this->roles = $roles;
    }

    /**
     * Gets roles detected
     *
     * @return string[]
     */
    public function getRoles(): array
    {
        return $this->roles;
    }
}
