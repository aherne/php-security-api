<?php

namespace Lucinda\WebSecurity\Configuration;

/**
 * Validates XML attribute values and converts them to the expected configuration types
 */
final class FieldValidator
{
    /**
     * Validates an integer attribute against an inclusive minimum and returns its value
     *
     * @param \SimpleXMLElement $xml XML tag containing the attribute
     * @param string $fieldName Attribute name
     * @param int $minValue Minimum accepted value, inclusive
     * @throws Exception If the attribute is missing, is not a valid integer or is below the minimum
     * @return int
     */
    public function getValidInteger(\SimpleXMLElement $xml, string $fieldName, int $minValue): int
    {
        $result = filter_var(
            (string) $xml[$fieldName],
            FILTER_VALIDATE_INT,
            ["options" => ["min_range" => $minValue]]
        );

        if ($result === false) {
            throw new Exception("Field '".$fieldName."' must be a positive integer");
        }

        return $result;
    }

    /**
     * Validates an integer 0/1 attribute and returns its boolean value
     *
     * The XML boolean format uses 0 for false and 1 for true; textual true/false values are rejected.
     *
     * @param \SimpleXMLElement $xml XML tag containing the attribute
     * @param string $fieldName Attribute name
     * @throws Exception If the attribute does not validate as integer 0 or 1
     * @return bool
     */
    public function getValidBoolean(\SimpleXMLElement $xml, string $fieldName): bool
    {
        $result = filter_var(
            (string) $xml[$fieldName],
            FILTER_VALIDATE_INT,
            ["options" => ["min_range" => 0]]
        );

        if ($result !==0 && $result !==1) {
            throw new Exception("Field '".$fieldName."' value can only be: 0 or 1");
        }

        return (bool) $result;
    }

    /**
     * Detects the backed enum case selected by an XML attribute
     *
     * @template T of \BackedEnum
     * @param \SimpleXMLElement $xml XML tag containing the attribute
     * @param string $fieldName Attribute name
     * @param class-string<T> $enumClass Backed enum class whose values are accepted
     * @throws Exception If the attribute value does not match an enum case
     * @return T
     */
    public function getValidEnum(\SimpleXMLElement $xml, string $fieldName, string $enumClass): \BackedEnum
    {
        $value = (string) $xml[$fieldName];

        $enum = $enumClass::tryFrom($value);

        if ($enum === null) {
            throw new Exception("Field '{$fieldName}' must be a member of: ".$enumClass);
        }

        return $enum;
    }
}