package com.webshield.api.mutation;

import com.webshield.api.models.ApiSchema;

import java.util.List;
import java.util.Random;

/**
 * String mutation operators providing character manipulations, boundary lengths,
 * special characters, quotes/delimiters, control characters, and Unicode edge cases.
 * Payloads are designed for safe, non-destructive API fuzzing and security assessment.
 */
public class StringMutation {

    public static final List<Character> SPECIAL_CHARACTERS = List.of(
            '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '-', '=',
            '[', ']', '{', '}', '|', ';', ':', '<', '>', '?', '~'
    );

    public static final List<String> QUOTES_AND_DELIMITERS = List.of(
            "'", "\"", "`", "\\", "/", ";", ",", ":", "|", "&", "&&", "||"
    );

    public static final List<String> UNICODE_SAMPLES = List.of(
            "\u00E9\u00E0\u00EE",               // Accented Latin: éàî
            "\u4E2D\u6587\u6D4B\u8BD5",         // CJK: 中文测试
            "\u0422\u0435\u0441\u0442",         // Cyrillic: Тест
            "\uD83D\uDE00\uD83D\uDEE1\uFE0F",   // Emojis: 😀🛡️
            "\u00A0\u200B\u200E",               // Non-breaking space, zero-width space, LTR mark
            "\uFEFF",                           // Byte Order Mark (BOM)
            "\uFFFF"                            // Unicode BMP maximum non-character
    );

    public static final List<String> CONTROL_CHARACTERS = List.of(
            "\u0000",                           // Null byte
            "\r",                               // Carriage return
            "\n",                               // Line feed
            "\r\n",                             // CRLF
            "\t",                               // Horizontal tab
            "\b",                               // Backspace
            "\f",                               // Form feed
            "\u001B"                            // Escape character
    );

    public static final List<String> WHITESPACE_SAMPLES = List.of(
            "   ",
            "\t",
            "\n",
            "\r\n",
            "  \t  \n  "
    );

    /**
     * Inserts one or more random characters into the input string.
     */
    public static String insertCharacters(String input, Random random) {
        String base = input != null ? input : "";
        char toInsert = (char) ('a' + random.nextInt(26));
        int pos = base.isEmpty() ? 0 : random.nextInt(base.length() + 1);
        return base.substring(0, pos) + toInsert + base.substring(pos);
    }

    /**
     * Deletes one or more characters from the input string.
     */
    public static String deleteCharacters(String input, Random random) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        if (input.length() == 1) {
            return "";
        }
        int pos = random.nextInt(input.length());
        return input.substring(0, pos) + input.substring(pos + 1);
    }

    /**
     * Replaces characters in the string with alternative characters.
     */
    public static String replaceCharacters(String input, Random random) {
        if (input == null || input.isEmpty()) {
            return "X";
        }
        int pos = random.nextInt(input.length());
        char original = input.charAt(pos);
        char replacement = original == 'Z' ? 'A' : (char) (original + 1);
        return input.substring(0, pos) + replacement + input.substring(pos + 1);
    }

    /**
     * Returns an empty string.
     */
    public static String toEmptyString() {
        return "";
    }

    /**
     * Injects whitespace (leading, trailing, or embedded) into the string.
     */
    public static String injectWhitespace(String input, Random random) {
        String ws = WHITESPACE_SAMPLES.get(random.nextInt(WHITESPACE_SAMPLES.size()));
        String base = input != null ? input : "";
        int mode = random.nextInt(3);
        return switch (mode) {
            case 0 -> ws + base;                  // Leading
            case 1 -> base + ws;                  // Trailing
            default -> {                          // Embedded
                int pos = base.isEmpty() ? 0 : random.nextInt(base.length() + 1);
                yield base.substring(0, pos) + ws + base.substring(pos);
            }
        };
    }

    /**
     * Expands the string length beyond boundary limits.
     */
    public static String expandLength(String input, int targetLength) {
        String base = (input != null && !input.isEmpty()) ? input : "A";
        int len = Math.max(targetLength, 256);
        StringBuilder sb = new StringBuilder(len);
        while (sb.length() < len) {
            sb.append(base);
        }
        return sb.substring(0, len);
    }

    /**
     * Truncates the string length below minimum threshold.
     */
    public static String truncateLength(String input, int targetLength) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        int len = Math.max(0, Math.min(targetLength, input.length() - 1));
        return input.substring(0, len);
    }

    /**
     * Injects special punctuation symbols.
     */
    public static String injectSpecialCharacters(String input, Random random) {
        char ch = SPECIAL_CHARACTERS.get(random.nextInt(SPECIAL_CHARACTERS.size()));
        String base = input != null ? input : "";
        int pos = base.isEmpty() ? 0 : random.nextInt(base.length() + 1);
        return base.substring(0, pos) + ch + base.substring(pos);
    }

    /**
     * Injects quote and delimiter characters.
     */
    public static String injectQuotesAndDelimiters(String input, Random random) {
        String delimiter = QUOTES_AND_DELIMITERS.get(random.nextInt(QUOTES_AND_DELIMITERS.size()));
        String base = input != null ? input : "";
        int pos = base.isEmpty() ? 0 : random.nextInt(base.length() + 1);
        return base.substring(0, pos) + delimiter + base.substring(pos);
    }

    /**
     * Injects Unicode edge cases and non-ASCII character sequences.
     */
    public static String injectUnicode(String input, Random random) {
        String sample = UNICODE_SAMPLES.get(random.nextInt(UNICODE_SAMPLES.size()));
        String base = input != null ? input : "";
        int pos = base.isEmpty() ? 0 : random.nextInt(base.length() + 1);
        return base.substring(0, pos) + sample + base.substring(pos);
    }

    /**
     * Injects control characters such as null bytes and CRLF.
     */
    public static String injectControlCharacters(String input, Random random) {
        String ctrl = CONTROL_CHARACTERS.get(random.nextInt(CONTROL_CHARACTERS.size()));
        String base = input != null ? input : "";
        int pos = base.isEmpty() ? 0 : random.nextInt(base.length() + 1);
        return base.substring(0, pos) + ctrl + base.substring(pos);
    }

    /**
     * Schema-aware application of a string mutation operator.
     */
    public static String apply(MutationOperatorType type, String input, ApiSchema schema, Random random) {
        return switch (type) {
            case STRING_INSERTION -> insertCharacters(input, random);
            case STRING_DELETION -> deleteCharacters(input, random);
            case STRING_REPLACEMENT -> replaceCharacters(input, random);
            case STRING_EMPTY -> toEmptyString();
            case STRING_WHITESPACE -> injectWhitespace(input, random);
            case STRING_EXPANSION -> {
                int target = (schema != null && schema.getMaxLength() != null)
                        ? schema.getMaxLength() + 50
                        : 512;
                yield expandLength(input, target);
            }
            case STRING_TRUNCATION -> {
                int target = (schema != null && schema.getMinLength() != null && schema.getMinLength() > 0)
                        ? Math.max(0, schema.getMinLength() - 1)
                        : 0;
                yield truncateLength(input, target);
            }
            case STRING_SPECIAL_CHARS -> injectSpecialCharacters(input, random);
            case STRING_QUOTES_DELIMITERS -> injectQuotesAndDelimiters(input, random);
            case STRING_UNICODE -> injectUnicode(input, random);
            case STRING_CONTROL_CHARS -> injectControlCharacters(input, random);
            default -> input;
        };
    }
}

