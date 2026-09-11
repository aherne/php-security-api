<?php

namespace Lucinda\WebSecurity\Configuration;

final class FieldValidator
{
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