<?php

namespace Lucinda\WebSecurity\Configuration;

/**
 * Parses comma-separated roles from XML child tags and indexes them by a configured attribute
 */
final class RolesDetector
{
    /**
     * @var array<array-key, string[]>
     */
    private array $roles;

    /**
     * Sets up the role map from the configured XML tags and identifying attribute
     *
     * @param \SimpleXMLElement $xml XML document containing the role definitions
     * @param string $parentTag Name of the parent tag, for example 'routes'
     * @param string $childTag Name of each role-bearing child tag, for example 'route'
     * @param string $requiredAttribute Attribute identifying each child, for example 'id'
     * @throws Exception If a matching child is missing its identifying attribute or roles
     */
    public function __construct(
        \SimpleXMLElement $xml,
        string $parentTag,
        string $childTag,
        string $requiredAttribute
    ) {
        $this->setRoles($xml, $parentTag, $childTag, $requiredAttribute);
    }

    /**
     * Detects each child's roles from its 'roles' attribute and stores them by the identifying attribute
     *
     * @param \SimpleXMLElement $xml XML document containing the role definitions
     * @param string $parentTag Name of the parent tag, for example 'routes'
     * @param string $childTag Name of each role-bearing child tag, for example 'route'
     * @param string $requiredAttribute Attribute identifying each child, for example 'id'
     * @throws Exception If a matching child is missing its identifying attribute or roles
     */
    private function setRoles(
        \SimpleXMLElement $xml,
        string $parentTag,
        string $childTag,
        string $requiredAttribute
    ): void {
        $info = $xml->xpath("//".$parentTag."/".$childTag);
        if (!empty($info)) {
            foreach ($info as $node) {
                $attributes = $node->attributes();
                if (empty($attributes[$requiredAttribute])) {
                    throw new Exception("XML tag ".$parentTag." > ".$childTag." requires attribute: ".$requiredAttribute);
                }

                if (empty($attributes['roles'])) {
                    throw new Exception("XML tag ".$parentTag." > ".$childTag." requires attribute: roles");
                }

                $tmp = (string) $attributes['roles'];
                $tmp= explode(",", $tmp);
                $roles = [];
                foreach ($tmp as $role) {
                    $roles[] = trim($role);
                }
                $this->roles[(string) $attributes[$requiredAttribute]] = $roles;
            }
        }
    }

    /**
     * Gets roles for an identifying attribute value, or an empty array when no match exists
     *
     * @param string $matchingValue Value of the identifying attribute to look up
     * @return string[]
     */
    public function getRoles(string $matchingValue): array
    {
        return $this->roles[$matchingValue] ?? [];
    }
}
    