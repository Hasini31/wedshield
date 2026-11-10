package com.webshield.api.mutation;

import com.webshield.api.models.ApiSchema;

import java.util.List;
import java.util.Random;

/**
 * Enum mutation operators providing valid substitutions, invalid values, casing shifts, empty, and null.
 */
public class EnumMutation {

    /**
     * Replaces current enum value with an alternative valid enum declared in schema.
     */
    public static String replaceValid(String current, ApiSchema schema, Random random) {
        if (schema == null || schema.getEnumValues().isEmpty()) {
            return current;
        }
        List<String> validEnums = schema.getEnumValues();
        List<String> alternatives = validEnums.stream()
                .filter(v -> current == null || !v.equalsIgnoreCase(current))
                .toList();

        if (alternatives.isEmpty()) {
            return validEnums.get(0);
        }
        int idx = random != null ? random.nextInt(alternatives.size()) : 0;
        return alternatives.get(idx);
    }

    /**
     * Injects an unlisted, invalid enum value.
     */
    public static String injectInvalid(String current, Random random) {
        if (current == null || current.isBlank()) {
            return "INVALID_ENUM_VALUE";
        }
        return current + "_UNKNOWN";
    }

    /**
     * Varies casing of the valid enum value (e.g. UPPERCASE -> lowercase, or vice versa).
     */
    public static String caseVariation(String current) {
        if (current == null || current.isBlank()) {
            return "invalid_case";
        }
        // If entirely uppercase, convert to lowercase; otherwise uppercase
        if (current.equals(current.toUpperCase())) {
            return current.toLowerCase();
        } else {
            return current.toUpperCase();
        }
    }

    /**
     * Returns an empty string.
     */
    public static String emptyValue() {
        return "";
    }

    /**
     * Injects null.
     */
    public static String nullValue() {
        return null;
    }

    /**
     * Schema-aware application of an enum mutation operator.
     */
    public static String apply(MutationOperatorType type, String current, ApiSchema schema, Random random) {
        return switch (type) {
            case ENUM_REPLACE_VALID -> replaceValid(current, schema, random);
            case ENUM_INJECT_INVALID -> injectInvalid(current, random);
            case ENUM_CASE_VARIATION -> caseVariation(current);
            case ENUM_EMPTY -> emptyValue();
            case ENUM_NULL -> nullValue();
            default -> current;
        };
    }
}

