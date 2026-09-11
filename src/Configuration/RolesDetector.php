<?php

namespace Lucinda\WebSecurity\Configuration;

/**
 * Detects roles from matching child tag or, if not found, gets default roles
 */
final class RolesDetector
{
    /*
     * @var array<string, string[]>
     */
    private array $roles;

    /**
     * Calls for roles detection
     *
     * @param  \SimpleXMLElement $xml
     * @param  string            $parentTag
     * @param  string            $childTag
     * @param  string            $requiredAttribute
     * @throws Exception
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
     * etects roles from matching child tag or, if not found, gets default roles
     *
     * @param  \SimpleXMLElement $xml
     * @param  string            $parentTag
     * @param  string            $childTag
     * @param  string            $requiredAttribute
     * @param  string   $matchingValue
     * @throws Exception
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
     * Gets roles detected
     *
     * @param string $matchingValue
     * @return string[]
     */
    public function getRoles(string $matchingValue): array
    {
        return $this->roles[$matchingValue] ?? [];
    }
}
    