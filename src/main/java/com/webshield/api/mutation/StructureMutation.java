package com.webshield.api.mutation;

import com.webshield.api.models.ApiSchema;

import java.util.*;

/**
 * Structural JSON mutations operating on deep-copied object maps and array representations.
 * Guarantees parent immutability, bounded size, and memory safety.
 */
public class StructureMutation {

    /**
     * Recursively deep-copies a JSON-compatible object structure (Maps, Lists, Primitives).
     */
    @SuppressWarnings("unchecked")
    public static Object deepCopy(Object obj) {
        if (obj == null) {
            return null;
        }
        if (obj instanceof Map<?, ?> map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                copy.put(key, deepCopy(entry.getValue()));
            }
            return copy;
        }
        if (obj instanceof List<?> list) {
            List<Object> copy = new ArrayList<>(list.size());
            for (Object item : list) {
                copy.add(deepCopy(item));
            }
            return copy;
        }
        // Strings, Numbers, Booleans are immutable
        return obj;
    }

    /**
     * Removes an optional property from a JSON object map.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> removeOptionalProperty(Map<String, Object> input, ApiSchema schema, Random random) {
        if (input == null || input.isEmpty()) {
            return input != null ? new LinkedHashMap<>(input) : new LinkedHashMap<>();
        }
        Map<String, Object> copy = (Map<String, Object>) deepCopy(input);
        Set<String> required = schema != null ? schema.getRequiredProperties() : Collections.emptySet();

        List<String> optionalKeys = copy.keySet().stream()
                .filter(k -> !required.contains(k))
                .toList();

        if (!optionalKeys.isEmpty()) {
            int idx = random != null ? random.nextInt(optionalKeys.size()) : 0;
            copy.remove(optionalKeys.get(idx));
        }
        return copy;
    }

    /**
     * Removes a required property from a JSON object map.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> removeRequiredProperty(Map<String, Object> input, ApiSchema schema, Random random) {
        if (input == null || input.isEmpty()) {
            return input != null ? new LinkedHashMap<>(input) : new LinkedHashMap<>();
        }
        Map<String, Object> copy = (Map<String, Object>) deepCopy(input);
        Set<String> required = schema != null ? schema.getRequiredProperties() : Collections.emptySet();

        List<String> requiredPresent = copy.keySet().stream()
                .filter(required::contains)
                .toList();

        if (!requiredPresent.isEmpty()) {
            int idx = random != null ? random.nextInt(requiredPresent.size()) : 0;
            copy.remove(requiredPresent.get(idx));
        } else {
            // Fallback: remove any key
            Iterator<String> it = copy.keySet().iterator();
            if (it.hasNext()) {
                it.next();
                it.remove();
            }
        }
        return copy;
    }

    /**
     * Adds an unexpected / undeclared property to a JSON object map.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> addUnexpectedProperty(Map<String, Object> input, Random random) {
        Map<String, Object> copy = input != null
                ? (Map<String, Object>) deepCopy(input)
                : new LinkedHashMap<>();

        int suffix = random != null ? random.nextInt(10000) : 101;
        String unexpectedKey = "__unexpected_property_" + suffix;
        copy.put(unexpectedKey, "unexpected_payload_value");
        return copy;
    }

    /**
     * Replaces an object structure with a primitive value.
     */
    public static Object replaceObjectWithPrimitive(Object input) {
        return "unexpected_primitive_replacement";
    }

    /**
     * Replaces a primitive value with a JSON object.
     */
    public static Object replacePrimitiveWithObject(Object input) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("unexpected_nested_key", "primitive_replaced");
        return map;
    }

    /**
     * Wraps a value or object in a JSON array.
     */
    public static List<Object> wrapInArray(Object input) {
        List<Object> list = new ArrayList<>();
        list.add(deepCopy(input));
        return list;
    }

    /**
     * Unwraps a JSON array into its first element.
     */
    public static Object unwrapArray(Object input) {
        if (input instanceof List<?> list && !list.isEmpty()) {
            return deepCopy(list.get(0));
        }
        return input;
    }

    /**
     * Modifies the length of an array (truncates, duplicates an item, or empties).
     */
    @SuppressWarnings("unchecked")
    public static List<Object> changeArrayLength(List<Object> input, Random random) {
        if (input == null || input.isEmpty()) {
            List<Object> emptyList = new ArrayList<>();
            emptyList.add("extra_array_item");
            return emptyList;
        }
        List<Object> copy = (List<Object>) deepCopy(input);
        int mode = random != null ? random.nextInt(3) : 0;

        switch (mode) {
            case 0 -> {
                // Truncate
                if (copy.size() > 1) {
                    copy.remove(copy.size() - 1);
                } else {
                    copy.clear();
                }
            }
            case 1 -> {
                // Duplicate an item
                copy.add(deepCopy(copy.get(0)));
            }
            default -> {
                // Clear array to empty
                copy.clear();
            }
        }
        return copy;
    }

    /**
     * Duplicates a nested structure inside an object map.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> duplicateNestedStructure(Map<String, Object> input, Random random) {
        if (input == null || input.isEmpty()) {
            return input != null ? new LinkedHashMap<>(input) : new LinkedHashMap<>();
        }
        Map<String, Object> copy = (Map<String, Object>) deepCopy(input);

        // Find any nested Map or List
        for (Map.Entry<String, Object> entry : copy.entrySet()) {
            if (entry.getValue() instanceof Map<?, ?> || entry.getValue() instanceof List<?>) {
                String dupKey = entry.getKey() + "_duplicated";
                copy.put(dupKey, deepCopy(entry.getValue()));
                return copy;
            }
        }

        // Fallback: duplicate any property
        Map.Entry<String, Object> first = copy.entrySet().iterator().next();
        copy.put(first.getKey() + "_copy", deepCopy(first.getValue()));
        return copy;
    }

    /**
     * Changes the data type of an embedded nested object structure.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> changeNestedObjectType(Map<String, Object> input, Random random) {
        if (input == null || input.isEmpty()) {
            return input != null ? new LinkedHashMap<>(input) : new LinkedHashMap<>();
        }
        Map<String, Object> copy = (Map<String, Object>) deepCopy(input);

        for (Map.Entry<String, Object> entry : copy.entrySet()) {
            if (entry.getValue() instanceof Map<?, ?>) {
                // Change Map to a List or string primitive
                boolean toArray = random == null || random.nextBoolean();
                if (toArray) {
                    copy.put(entry.getKey(), List.of("converted_nested_array_item"));
                } else {
                    copy.put(entry.getKey(), "converted_nested_primitive_value");
                }
                return copy;
            }
            if (entry.getValue() instanceof List<?>) {
                // Change List to a Map
                Map<String, Object> obj = new LinkedHashMap<>();
                obj.put("converted_from_list", true);
                copy.put(entry.getKey(), obj);
                return copy;
            }
        }

        // Fallback: convert first property to an object if primitive, or vice-versa
        Map.Entry<String, Object> first = copy.entrySet().iterator().next();
        if (first.getValue() instanceof Map<?, ?>) {
            copy.put(first.getKey(), "primitive_value");
        } else {
            copy.put(first.getKey(), Map.of("unexpected_key", 123));
        }
        return copy;
    }
}

