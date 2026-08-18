<?php

namespace Lucinda\WebSecurity\Configuration;

/**
 * Detects roles from matching child tag or, if not found, gets default roles
 */
final class RolesDetector
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
     * @throws Exception
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
     * @throws Exception
     */
    private function setRoles(
        \SimpleXMLElement $xml,
        string $parentTag,
        string $childTag,
        string $requiredAttribute,
        int|string|null $matchingValue
    ): void {
        $roles = [];
        $info = $xml->xpath("//".$parentTag."/".$childTag);
        if (!empty($info)) {
            foreach ($info as $node) {
                $attributes = $node->attributes();
                if (!isset($attributes[$requiredAttribute]) || (string) $attributes[$requiredAttribute] !== (string) $matchingValue) {
                    continue;
                }

                if (empty($attributes['roles'])) {
                    throw new Exception("XML tag ".$parentTag." > ".$childTag." requires attribute: roles");
                }

                $tmp = (string) $attributes['roles'];
                $tmp= explode(",", $tmp);
                foreach ($tmp as $role) {
                    $roles[] = trim($role);
                }
                break; // no point moving forward
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
