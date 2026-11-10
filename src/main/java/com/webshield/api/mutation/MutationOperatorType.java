package com.webshield.api.mutation;

/**
 * Specific mutation operators supported by the API Input Mutation Engine.
 */
public enum MutationOperatorType {

    // =========================================================================
    // String Mutation Operators
    // =========================================================================
    STRING_INSERTION(MutationCategory.STRING, "Character insertion at arbitrary positions"),
    STRING_DELETION(MutationCategory.STRING, "Character deletion from input string"),
    STRING_REPLACEMENT(MutationCategory.STRING, "Character substitution with unexpected characters"),
    STRING_EMPTY(MutationCategory.STRING, "Empty string substitution"),
    STRING_WHITESPACE(MutationCategory.STRING, "Leading, trailing, or embedded whitespace injection"),
    STRING_EXPANSION(MutationCategory.STRING, "Length expansion exceeding normal boundaries"),
    STRING_TRUNCATION(MutationCategory.STRING, "Length truncation below minimum required size"),
    STRING_SPECIAL_CHARS(MutationCategory.STRING, "Injection of special characters and symbols"),
    STRING_QUOTES_DELIMITERS(MutationCategory.STRING, "Injection of quotes, slashes, and delimiter symbols"),
    STRING_UNICODE(MutationCategory.STRING, "Injection of multi-byte Unicode, non-ASCII, and boundary characters"),
    STRING_CONTROL_CHARS(MutationCategory.STRING, "Injection of control characters including null bytes, tabs, and newlines"),

    // =========================================================================
    // Numeric Mutation Operators
    // =========================================================================
    NUMERIC_INCREMENT(MutationCategory.NUMERIC, "Increment numeric value by unit delta"),
    NUMERIC_DECREMENT(MutationCategory.NUMERIC, "Decrement numeric value by unit delta"),
    NUMERIC_SIGN_REVERSAL(MutationCategory.NUMERIC, "Reverse numeric sign (+/-)"),
    NUMERIC_ZERO(MutationCategory.NUMERIC, "Zero value substitution"),
    NUMERIC_NEGATIVE(MutationCategory.NUMERIC, "Negative value substitution"),
    NUMERIC_BOUNDARY_MIN_MAX(MutationCategory.NUMERIC, "Substitution with schema minimum or maximum boundary"),
    NUMERIC_OUTSIDE_BOUNDS(MutationCategory.NUMERIC, "Value immediately outside schema minimum/maximum bounds"),
    NUMERIC_OVERFLOW(MutationCategory.NUMERIC, "Integer overflow boundary substitution (MIN/MAX INT/LONG)"),
    NUMERIC_LARGE_VALUE(MutationCategory.NUMERIC, "Very large numeric value substitution"),
    NUMERIC_FLOATING_POINT_EDGE(MutationCategory.NUMERIC, "Floating-point edge case (NaN, Infinity, -0.0, extremes)"),

    // =========================================================================
    // Boolean Mutation Operators
    // =========================================================================
    BOOLEAN_INVERT(MutationCategory.BOOLEAN, "Invert boolean value (true <-> false)"),
    BOOLEAN_REMOVE_OPTIONAL(MutationCategory.BOOLEAN, "Removal of optional boolean field"),
    BOOLEAN_NULL_INJECT(MutationCategory.BOOLEAN, "Injection of null into boolean field"),

    // =========================================================================
    // Enum Mutation Operators
    // =========================================================================
    ENUM_REPLACE_VALID(MutationCategory.ENUM, "Replacement with an alternative declared valid enum value"),
    ENUM_INJECT_INVALID(MutationCategory.ENUM, "Injection of an unlisted, invalid enum value"),
    ENUM_CASE_VARIATION(MutationCategory.ENUM, "Casing variation of valid enum constant (uppercase/lowercase)"),
    ENUM_EMPTY(MutationCategory.ENUM, "Empty string substitution for enum field"),
    ENUM_NULL(MutationCategory.ENUM, "Null substitution for enum field"),

    // =========================================================================
    // Structure Mutation Operators
    // =========================================================================
    STRUCTURE_REMOVE_OPTIONAL(MutationCategory.STRUCTURE, "Remove an optional property from a JSON object"),
    STRUCTURE_REMOVE_REQUIRED(MutationCategory.STRUCTURE, "Remove a required property from a JSON object"),
    STRUCTURE_ADD_UNEXPECTED(MutationCategory.STRUCTURE, "Inject an undeclared property into a JSON object"),
    STRUCTURE_OBJECT_TO_PRIMITIVE(MutationCategory.STRUCTURE, "Replace a JSON object with a primitive value"),
    STRUCTURE_PRIMITIVE_TO_OBJECT(MutationCategory.STRUCTURE, "Replace a primitive value with a JSON object"),
    STRUCTURE_WRAP_IN_ARRAY(MutationCategory.STRUCTURE, "Wrap a value or object in a JSON array"),
    STRUCTURE_UNWRAP_ARRAY(MutationCategory.STRUCTURE, "Unwrap a JSON array into its first element"),
    STRUCTURE_CHANGE_ARRAY_LENGTH(MutationCategory.STRUCTURE, "Change array element count (truncate, duplicate, clear)"),
    STRUCTURE_DUPLICATE_NESTED(MutationCategory.STRUCTURE, "Duplicate a nested structure property"),
    STRUCTURE_CHANGE_NESTED_TYPE(MutationCategory.STRUCTURE, "Alter the data type of an embedded nested structure");

    private final MutationCategory category;
    private final String description;

    MutationOperatorType(MutationCategory category, String description) {
        this.category = category;
        this.description = description;
    }

    public MutationCategory getCategory() {
        return category;
    }

    public String getDescription() {
        return description;
    }
}

